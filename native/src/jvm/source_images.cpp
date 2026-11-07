#include "himitsu/jvm/source_images.hpp"
#include "himitsu/jvm/class_control.hpp"
#include "himitsu/jvm/jvmti_guard.hpp"
#include "himitsu/core/native_log.hpp"
#include "himitsu/core/runtime_state.hpp"
#include <array>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <cwchar>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>

namespace {
using Bytes = std::vector<unsigned char>;
std::shared_mutex images_lock;
std::map<std::string, std::shared_ptr<const Bytes>, std::less<>> images;
std::mutex initialization_lock;
std::wstring initialized_archive;
std::atomic<bool> source_active{false};
constexpr std::size_t max_image = 16 * 1024 * 1024;
bool own(const std::string& name) { return name.rfind("com/himitsu/secret/", 0) == 0; }

// Bounded constant-pool parsing; the name is authenticated along with payload bytes.
std::string class_name(const unsigned char* data, std::size_t size) {
    if (size < 12 || size > max_image || std::memcmp(data, "\xCA\xFE\xBA\xBE", 4) != 0) return {};
    std::size_t p = 8;
    auto u2 = [&]() -> unsigned { if (p + 2 > size) { p = size + 1; return 0; }
        unsigned n = (unsigned(data[p]) << 8) | data[p+1]; p += 2; return n; };
    unsigned count = u2();
    std::vector<std::string> strings(count);
    std::vector<unsigned> classes(count);
    for (unsigned i=1; i<count && p<size; ++i) {
        unsigned tag=data[p++];
        switch (tag) {
        case 1: { unsigned n=u2(); if(p+n>size) return {}; strings[i].assign(reinterpret_cast<const char*>(data+p),n); p+=n; break; }
        case 7: classes[i]=u2(); break;
        case 8: case 16: case 19: case 20: p+=2; break;
        case 3: case 4: case 9: case 10: case 11: case 12: case 17: case 18: p+=4; break;
        case 5: case 6: p+=8; ++i; break;
        case 15: p+=3; break;
        default: return {};
        }
    }
    if(p+6>size) return {};
    u2(); unsigned type=u2();
    if(type>=count || classes[type]>=count) return {};
    return strings[classes[type]];
}
bool store(const std::string& name, Bytes data) {
    if(name.empty() || class_name(data.data(),data.size())!=name) return false;
    std::unique_lock lock(images_lock);
    auto found=images.find(name);
    if(found!=images.end()) return *found->second==data; // A baseline never silently changes.
    images.emplace(name,std::make_shared<const Bytes>(std::move(data))); return true;
}
std::shared_ptr<const Bytes> lookup(const std::string& name) {
    std::shared_lock lock(images_lock);auto found=images.find(name);
    return found==images.end()?nullptr:found->second;
}
Bytes byte_array(JNIEnv* env,jobject value) {
    if(value==nullptr || env->ExceptionCheck()) return {};
    jclass array=env->FindClass("[B");
    bool valid=array!=nullptr && env->IsInstanceOf(value,array);
    if(array)env->DeleteLocalRef(array);
    if(!valid)return {};
    jsize size=env->GetArrayLength(static_cast<jbyteArray>(value));
    if(size<=0 || size>max_image)return {};
    Bytes result(size);env->GetByteArrayRegion(static_cast<jbyteArray>(value),0,size,reinterpret_cast<jbyte*>(result.data()));
    return env->ExceptionCheck()?Bytes{}:result;
}
Bytes read_entry(JNIEnv* env,jstring archive,const std::string& name) {
    if(env->PushLocalFrame(32)!=JNI_OK)return {};
    jstring entry=env->NewStringUTF(name.c_str());
    jobject result=entry?himitsu::jvm::read_zip_entry(env,archive,entry):nullptr;
    Bytes bytes=byte_array(env,result);
    if(env->ExceptionCheck()){env->ExceptionDescribe();env->ExceptionClear();}
    env->PopLocalFrame(nullptr);return bytes;
}
bool core_image(const std::string& name) {
    return name=="java/lang/invoke/MethodHandles$Lookup" || name=="java/lang/invoke/VarHandle"
        || name=="jdk/internal/misc/Unsafe" || name=="sun/misc/Unsafe"
        || name=="java/lang/reflect/Method" || name=="java/lang/reflect/Field"
        || name=="java/lang/ClassLoader";
}
Bytes core_resource(JNIEnv* env,jclass type,const std::string& name) {
    if(env->PushLocalFrame(32)!=JNI_OK)return {};
    jclass class_type=env->FindClass("java/lang/Class");
    jmethodID resource=class_type?env->GetMethodID(class_type,"getResourceAsStream","(Ljava/lang/String;)Ljava/io/InputStream;"):nullptr;
    jmethodID module_method=class_type?env->GetMethodID(class_type,"getModule","()Ljava/lang/Module;"):nullptr;
    jobject module=module_method?env->CallObjectMethod(type,module_method):nullptr;
    jclass module_type=env->FindClass("java/lang/Module");
    jmethodID module_name=module_type?env->GetMethodID(module_type,"getName","()Ljava/lang/String;"):nullptr;
    auto label=module&&module_name?static_cast<jstring>(env->CallObjectMethod(module,module_name)):nullptr;
    const char* chars=label?env->GetStringUTFChars(label,nullptr):nullptr;
    bool trusted=chars&&(std::strcmp(chars,"java.base")==0||std::strcmp(chars,"jdk.unsupported")==0);
    if(chars)env->ReleaseStringUTFChars(label,chars);
    Bytes bytes;
    if(trusted && resource && !env->ExceptionCheck()) {
        jstring path=env->NewStringUTF(("/"+name+".class").c_str());
        jobject stream=path?env->CallObjectMethod(type,resource,path):nullptr;
        jclass input_type=env->FindClass("java/io/InputStream");
        jmethodID read=input_type?env->GetMethodID(input_type,"readAllBytes","()[B"):nullptr;
        jmethodID close=input_type?env->GetMethodID(input_type,"close","()V"):nullptr;
        if(stream&&read&&close&&!env->ExceptionCheck()) {
            bytes=byte_array(env,env->CallObjectMethod(stream,read));
            if(env->ExceptionCheck()){env->ExceptionDescribe();env->ExceptionClear();bytes.clear();}
            env->CallVoidMethod(stream,close);
        }
    }
    if(env->ExceptionCheck()){env->ExceptionDescribe();env->ExceptionClear();bytes.clear();}
    env->PopLocalFrame(nullptr);return bytes;
}
bool restore_loaded(JNIEnv* env,jvmtiEnv* jvmti) {
    jint count=0;jclass* classes=nullptr;
    if(jvmti->GetLoadedClasses(&count,&classes)!=JVMTI_ERROR_NONE)return false;
    bool success=true;
    for(jint i=0;i<count;++i) {
        char* signature=nullptr;
        if(jvmti->GetClassSignature(classes[i],&signature,nullptr)==JVMTI_ERROR_NONE&&signature) {
            std::string name(signature);jvmti->Deallocate(reinterpret_cast<unsigned char*>(signature));
            if(name.size()>2&&name.front()=='L'&&name.back()==';') {
                name=name.substr(1,name.size()-2);
                const bool jdk=core_image(name);
                if(jdk) {
                    if(!store(name,core_resource(env,classes[i],name))) {
                        HIMITSU_LOG_ERROR("SourceShield","JDK image unavailable: %s",name.c_str());success=false;
                    }
                }
                auto source=lookup(name);
                if(source) {
                    jboolean modifiable=JNI_FALSE;
                    jvmtiError error=jvmti->IsModifiableClass(classes[i],&modifiable);
                    if(error==JVMTI_ERROR_NONE&&modifiable) {
                        if(jdk) error=himitsu::jvm::trusted_retransform_classes(1,&classes[i]);
                        else {
                            jvmtiClassDefinition def{classes[i],static_cast<jint>(source->size()),source->data()};
                            error=himitsu::jvm::trusted_redefine_classes(1,&def);
                        }
                    } else if(error==JVMTI_ERROR_NONE) error=JVMTI_ERROR_UNMODIFIABLE_CLASS;
                    HIMITSU_LOG_INFO("SourceShield","Restore %s: jvmti=%d",name.c_str(),error);
                    success=(error==JVMTI_ERROR_NONE)&&success;
                }
            }
        }
        env->DeleteLocalRef(classes[i]);
    }
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(classes));return success;
}
}
namespace himitsu::jvm {
bool source_images_active() { return source_active.load(std::memory_order_acquire); }
bool remember_owned_image(const unsigned char* bytes,std::size_t size) {
    std::string name=class_name(bytes,size);
    return own(name)&&store(name,Bytes(bytes,bytes+size));
}
bool apply_source_image(JNIEnv* env,jvmtiEnv* jvmti,jobject loader,jclass redefining,const char* name,jint length,const unsigned char* input,
        jint* output_length,unsigned char** output) {
    if(name==nullptr)return false;
    std::shared_ptr<const Bytes> bytes;
    if(std::strcmp(name,"net/minecraftforge/eventbus/SecretEventBusBridge")==0) {
        auto& state=himitsu::core::RuntimeState::instance();himitsu::core::RuntimeState::ReferenceRead read(state,env);
        if(read->event_image && env->IsSameObject(loader,read->event_loader)
            && (!redefining || (read->event_bridge && env->IsSameObject(redefining,read->event_bridge))))bytes=read->event_image;
    } else {
        if(std::strncmp(name,"com/himitsu/secret/",19)!=0&&!core_image(name))return false;
        bytes=lookup(name);
    }
    if(!bytes)return false;
    if(length==static_cast<jint>(bytes->size())&&std::memcmp(input,bytes->data(),bytes->size())==0)return true;
    unsigned char* replacement=nullptr;
    if(jvmti->Allocate(static_cast<jlong>(bytes->size()),&replacement)!=JVMTI_ERROR_NONE)return false;
    std::memcpy(replacement,bytes->data(),bytes->size());
    *output_length=static_cast<jint>(bytes->size());*output=replacement;
    HIMITSU_LOG_WARNING("SourceShield","Restored class bytes: %s",name);return true;
}
namespace {
using State=himitsu::core::RuntimeState;
constexpr const char* event_name="net/minecraftforge/eventbus/SecretEventBusBridge";
constexpr const char* installer_name="com/himitsu/secret/core/EventBusBridge";
std::atomic<bool> event_installing{false};
std::atomic<unsigned long long> next_binding_report{0};
template<class Change> bool change_sources(JNIEnv* env,Change change) {
    auto& state=State::instance();
    for(unsigned retry=0;retry<8 && !state.shutting_down();++retry) {
        State::ReferenceRead read(state,env);auto next=std::make_unique<State::References>(*read.get());
        if(!change(*read.get(),*next))return false;
        if(state.publish_references(read.get(),next))return true;
    }
    return false;
}
jobject source_failure(JNIEnv* env,const char* message) {
    if(env->ExceptionCheck()){auto error=env->ExceptionOccurred();env->ExceptionClear();return error;}
    return new_exception(env,"java/lang/IllegalStateException",message);
}
bool installer_caller(JNIEnv* env,const State::References& refs) {
    if(!refs.event_installer)return false;
    auto* ti=State::instance().jvmti();jvmtiFrameInfo frames[32]{};jint count=0;
    if(!ti || ti->GetStackTrace(nullptr,0,32,frames,&count)!=JVMTI_ERROR_NONE)return false;
    for(jint i=0;i<count;++i) {
        jclass type=nullptr;if(ti->GetMethodDeclaringClass(frames[i].method,&type)!=JVMTI_ERROR_NONE)return false;
        bool owner=env->IsSameObject(type,refs.event_installer);env->DeleteLocalRef(type);
        if(owner) {
            char* name=nullptr;char* signature=nullptr;
            auto error=ti->GetMethodName(frames[i].method,&name,&signature,nullptr);
            bool ok=error==JVMTI_ERROR_NONE && name && signature && !std::strcmp(name,"defineAndBind") && !std::strcmp(signature,"()Ljava/lang/Class;");
            if(name)ti->Deallocate(reinterpret_cast<unsigned char*>(name));if(signature)ti->Deallocate(reinterpret_cast<unsigned char*>(signature));
            return ok;
        }
    }
    return false;
}
bool binding_matches(JNIEnv* env,const State::References& refs) {
    auto value=env->GetStaticObjectField(refs.event_bridge,refs.event_field);
    bool ok=value && env->IsInstanceOf(value,refs.event_array_type) && env->GetArrayLength(static_cast<jarray>(value))==2;
    for(int i=0;ok && i<2;++i) {
        auto handle=env->GetObjectArrayElement(static_cast<jobjectArray>(value),i);
        ok=env->IsSameObject(handle,refs.event_handles[i]);if(handle)env->DeleteLocalRef(handle);
    }
    if(value)env->DeleteLocalRef(value);return ok && !env->ExceptionCheck();
}
}
bool remember_game_bootstrap(JNIEnv* env,jclass bootstrap) {
    auto* ti=State::instance().jvmti();jobject loader=nullptr;
    if(!ti || ti->GetClassLoader(bootstrap,&loader)!=JVMTI_ERROR_NONE)return false;
    auto owner=static_cast<jclass>(env->NewGlobalRef(bootstrap));auto global=loader?env->NewGlobalRef(loader):nullptr;
    if(loader)env->DeleteLocalRef(loader);
    if(!owner || env->ExceptionCheck()){if(owner)env->DeleteGlobalRef(owner);if(global)env->DeleteGlobalRef(global);return false;}
    bool reused=false;
    bool ok=change_sources(env,[&](const auto& before,auto& next){
        if(before.bootstrap){reused=true;return env->IsSameObject(before.bootstrap,bootstrap)==JNI_TRUE;}
        next.bootstrap=owner;next.game_loader=global;return true;
    });
    if(!ok || reused){env->DeleteGlobalRef(owner);if(global)env->DeleteGlobalRef(global);}return ok;
}
bool remember_defined_installer(JNIEnv* env,jobject loader,jclass type,const unsigned char* data,std::size_t size) {
    if(class_name(data,size)!=installer_name)return true;
    auto expected=lookup(installer_name);
    if(!expected || expected->size()!=size || std::memcmp(expected->data(),data,size))return false;
    auto global=static_cast<jclass>(env->NewGlobalRef(type));if(!global)return false;
    bool reused=false;
    bool ok=change_sources(env,[&](const auto& before,auto& next){
        if(!before.bootstrap || !env->IsSameObject(loader,before.game_loader))return false;
        if(before.event_installer){reused=true;return env->IsSameObject(before.event_installer,type)==JNI_TRUE;}
        next.event_installer=global;return true;
    });
    if(!ok || reused)env->DeleteGlobalRef(global);return ok;
}
bool maintain_event_bridge(JNIEnv* env) {
    auto& state=State::instance();if(state.shutting_down())return false;
    State::ReferenceRead read(state,env);if(!read->event_bridge || !read->event_field)return true;
    if(binding_matches(env,*read.get()))return true;
    if(env->ExceptionCheck())env->ExceptionClear();
    auto component=env->FindClass("java/lang/invoke/MethodHandle");
    auto array=component?env->NewObjectArray(2,component,nullptr):nullptr;
    if(component)env->DeleteLocalRef(component);
    if(array)for(int i=0;i<2;++i)env->SetObjectArrayElement(array,i,read->event_handles[i]);
    bool ok=array && !env->ExceptionCheck() && !state.shutting_down();
    if(ok)env->SetStaticObjectField(read->event_bridge,read->event_field,array);
    if(array)env->DeleteLocalRef(array);ok=ok && !env->ExceptionCheck() && binding_matches(env,*read.get());
    if(env->ExceptionCheck())env->ExceptionClear();
    auto now=GetTickCount64(),prior=next_binding_report.load(std::memory_order_acquire);
    if(now>=prior && next_binding_report.compare_exchange_strong(prior,now+10000))
        HIMITSU_LOG_WARNING("SourceShield","Event bridge binding %s",ok?"restored":"NOT_RECOVERED");
    return ok;
}
jobject verify_event_bridge(JNIEnv* env) {
    auto& state=State::instance();State::ReferenceRead read(state,env);
    if(!installer_caller(env,*read.get()))return new_exception(env,"java/lang/SecurityException","Event bridge installer identity required");
    if(!read->event_bridge || !maintain_event_bridge(env))return source_failure(env,"Event bridge not ready");
    return env->NewLocalRef(read->event_bridge);
}
jobject define_event_bridge(JNIEnv* env,jbyteArray source,jclass bus,jobjectArray supplied) {
    auto& state=State::instance();State::ReferenceRead admission(state,env);
    if(!installer_caller(env,*admission.get()))return new_exception(env,"java/lang/SecurityException","Event bridge installer identity required");
    if(admission->event_bridge)return verify_event_bridge(env);
    bool idle=false;if(!event_installing.compare_exchange_strong(idle,true))return source_failure(env,"Event bridge definition in progress");
    std::array<jobject,6> globals{};std::uint64_t generation=0;bool pending=false,committed=false;
    auto cleanup=[&] {
        if(pending && !committed)change_sources(env,[&](const auto& before,auto& next){
            if(before.event_generation!=generation || before.event_bridge)return false;
            next.event_image.reset();next.event_loader=nullptr;next.event_bus=nullptr;next.event_handles[0]=next.event_handles[1]=nullptr;return true;
        });
        for(auto global:globals)if(global)env->DeleteGlobalRef(global);
        event_installing.store(false,std::memory_order_release);
    };
    try {
        jobject result=[&]()->jobject {
            auto bytes=byte_array(env,source);
            if(class_name(bytes.data(),bytes.size())!=event_name || !bus || !supplied || env->GetArrayLength(supplied)!=2)
                return source_failure(env,"Invalid event bridge definition");
            auto first=env->GetObjectArrayElement(supplied,0),second=env->GetObjectArrayElement(supplied,1);
            auto validate=env->GetStaticMethodID(admission->event_installer,"validate","(Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodHandle;)V");
            if(!first || !second || !validate)return source_failure(env,"Incomplete event handlers");
            env->CallStaticVoidMethod(admission->event_installer,validate,first,second);
            if(env->ExceptionCheck())return source_failure(env,"Invalid event handlers");
            jobject loader=nullptr;auto* ti=state.jvmti();
            char* signature=nullptr;
            bool bus_ok=ti && ti->GetClassSignature(bus,&signature,nullptr)==JVMTI_ERROR_NONE && signature && !std::strcmp(signature,"Lnet/minecraftforge/eventbus/EventBus;");
            if(signature)ti->Deallocate(reinterpret_cast<unsigned char*>(signature));
            if(!bus_ok || ti->GetClassLoader(bus,&loader)!=JVMTI_ERROR_NONE)return source_failure(env,"Unexpected EventBus class");
            globals[0]=loader?env->NewGlobalRef(loader):nullptr;globals[1]=env->NewGlobalRef(bus);
            globals[2]=env->NewGlobalRef(first);globals[3]=env->NewGlobalRef(second);
            if((loader&&!globals[0]) || !globals[1] || !globals[2] || !globals[3])return source_failure(env,"Event bridge references unavailable");
            auto image=std::make_shared<const Bytes>(std::move(bytes));
            pending=change_sources(env,[&](const auto& before,auto& next){
                if(before.event_image || before.event_bridge)return false;
                generation=before.event_generation+1;next.event_generation=generation;next.event_image=image;
                next.event_loader=globals[0];next.event_bus=static_cast<jclass>(globals[1]);next.event_handles[0]=globals[2];next.event_handles[1]=globals[3];return true;
            });
            if(!pending)return source_failure(env,"Event bridge publication refused");
            for(int i=0;i<4;++i)globals[i]=nullptr;
            auto bridge=env->DefineClass(event_name,loader,reinterpret_cast<const jbyte*>(image->data()),static_cast<jsize>(image->size()));
            if(!bridge || env->ExceptionCheck())return source_failure(env,"Event bridge definition conflict");
            auto field=env->GetStaticFieldID(bridge,"handlers","[Ljava/lang/invoke/MethodHandle;");jint modifiers=0;
            if(!field || ti->GetFieldModifiers(bridge,field,&modifiers)!=JVMTI_ERROR_NONE || modifiers!=0x004A)
                return source_failure(env,"Invalid event bridge field");
            auto component=env->FindClass("java/lang/invoke/MethodHandle");auto array=component?env->NewObjectArray(2,component,nullptr):nullptr;
            if(!array)return source_failure(env,"Event bridge binding allocation failed");
            env->SetObjectArrayElement(array,0,first);env->SetObjectArrayElement(array,1,second);
            env->SetStaticObjectField(bridge,field,array);
            if(env->ExceptionCheck())return source_failure(env,"Event bridge binding failed");
            globals[4]=env->NewGlobalRef(bridge);auto array_class=env->GetObjectClass(array);globals[5]=env->NewGlobalRef(array_class);
            if(!globals[4] || !globals[5])return source_failure(env,"Event bridge identity unavailable");
            committed=change_sources(env,[&](const auto& before,auto& next){
                if(before.event_generation!=generation || before.event_image!=image || before.event_bridge)return false;
                next.event_bridge=static_cast<jclass>(globals[4]);next.event_array_type=static_cast<jclass>(globals[5]);next.event_field=field;return true;
            });
            if(!committed)return source_failure(env,"Event bridge commit lost generation");
            globals[4]=globals[5]=nullptr;
            HIMITSU_LOG_INFO("SourceShield","Event bridge registered: exact loader/class, generation=%llu",generation);return bridge;
        }();
        cleanup();return result;
    } catch(...) {cleanup();throw;}
}
bool load_source_images(JNIEnv* env,jvmtiEnv* jvmti,const wchar_t* archive) {
    if(!archive||!*archive)return false;
    {
        std::lock_guard lock(initialization_lock);
        if(!initialized_archive.empty())return initialized_archive==archive;
    }
    // Identical concurrent captures are idempotent in store(). No initialization
    // mutex may be held during Java ZIP reads or JVMTI class restoration.
    jstring path=env->NewString(reinterpret_cast<const jchar*>(archive),static_cast<jsize>(std::wcslen(archive)));
    if(!path)return false;
    Bytes index=read_entry(env,path,"META-INF/secret-bootstrap.list");
    bool ok=!index.empty()&&index.size()<65536;
    std::string rows(index.begin(),index.end());std::size_t start=0;unsigned captured=0;
    while(ok&&start<rows.size()) {
        auto end=rows.find('\n',start);if(end==std::string::npos)end=rows.size();
        std::string entry=rows.substr(start,end-start);start=end+1;
        if(entry.empty())continue;
        if(entry.size()<7||entry.substr(entry.size()-6)!=".class"||!own(entry)||entry.find("..")!=std::string::npos){ok=false;break;}
        Bytes bytes=read_entry(env,path,entry);
        ok=store(entry.substr(0,entry.size()-6),std::move(bytes));++captured;
    }
    env->DeleteLocalRef(path);
    if(ok)ok=trusted_set_event_notification_mode(JVMTI_ENABLE,JVMTI_EVENT_CLASS_FILE_LOAD_HOOK,nullptr)==JVMTI_ERROR_NONE;
    if(ok)ok=restore_loaded(env,jvmti);
    if(ok) {
        std::lock_guard lock(initialization_lock);
        if(initialized_archive.empty()) initialized_archive=archive;
        ok=initialized_archive==archive;
        if(ok) source_active.store(true,std::memory_order_release);
    }
    HIMITSU_LOG_INFO("SourceShield","Bootstrap source images=%u, ready=%s",captured,ok?"true":"false");
    return ok;
}
}
