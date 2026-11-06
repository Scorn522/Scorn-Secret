#include "himitsu/jvm/source_images.hpp"
#include "himitsu/jvm/class_control.hpp"
#include "himitsu/jvm/jvmti_guard.hpp"
#include "himitsu/core/native_log.hpp"
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
bool apply_source_image(jvmtiEnv* jvmti,const char* name,jint length,const unsigned char* input,
        jint* output_length,unsigned char** output) {
    if(name==nullptr)return false;
    if(std::strncmp(name,"com/himitsu/secret/",19)!=0&&!core_image(name))return false;
    auto bytes=lookup(name);if(!bytes)return false;
    if(length==static_cast<jint>(bytes->size())&&std::memcmp(input,bytes->data(),bytes->size())==0)return true;
    unsigned char* replacement=nullptr;
    if(jvmti->Allocate(static_cast<jlong>(bytes->size()),&replacement)!=JVMTI_ERROR_NONE)return false;
    std::memcpy(replacement,bytes->data(),bytes->size());
    *output_length=static_cast<jint>(bytes->size());*output=replacement;
    HIMITSU_LOG_WARNING("SourceShield","Restored class bytes: %s",name);return true;
}
bool load_source_images(JNIEnv* env,jvmtiEnv* jvmti,const wchar_t* archive) {
    if(!archive||!*archive)return false;
    std::lock_guard lock(initialization_lock);
    if(!initialized_archive.empty())return initialized_archive==archive;
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
    if(ok){initialized_archive=archive;source_active.store(true,std::memory_order_release);}
    HIMITSU_LOG_INFO("SourceShield","Bootstrap source images=%u, ready=%s",captured,ok?"true":"false");
    return ok;
}
}
