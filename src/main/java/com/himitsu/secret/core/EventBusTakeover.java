package com.himitsu.secret.core;

import com.himitsu.secret.client.render.ForgeRenderBridge;
import com.himitsu.secret.network.NetworkLifecycle;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import net.minecraftforge.api.distmarker.Dist;
import net.minecraftforge.event.TickEvent;
import net.minecraftforge.event.entity.player.PlayerEvent;
import net.minecraftforge.event.entity.item.ItemTossEvent;
import net.minecraftforge.event.level.LevelEvent;
import net.minecraftforge.eventbus.EventBus;
import net.minecraftforge.eventbus.api.Event;
import net.minecraftforge.eventbus.api.EventPriority;
import net.minecraftforge.eventbus.api.IEventBus;
import net.minecraftforge.eventbus.api.IEventBusInvokeDispatcher;
import net.minecraftforge.eventbus.api.IEventExceptionHandler;
import net.minecraftforge.eventbus.api.IEventListener;
import net.minecraftforge.fml.loading.FMLEnvironment;
import net.minecraftforge.fml.event.IModBusEvent;

public final class EventBusTakeover {
    private static final List<Handler<?>> HANDLERS = new ArrayList<>();
    private static final AtomicBoolean REGISTERED = new AtomicBoolean();
    private static final Field BUS_ID = field("busID");
    private static final Field SHUTDOWN = field("shutdown");
    private static final Field CHECK_TYPES = field("checkTypesOnDispatch");
    private static final Field BASE_TYPE = field("baseType");
    private static final Field TRACK_PHASES = field("trackPhases");
    private static final Field EXCEPTION_HANDLER = field("exceptionHandler");
    private static final Field LISTENERS = field("listeners");

    private EventBusTakeover() {
    }

    public static synchronized void registerRequiredHandlers() {
        if (!REGISTERED.compareAndSet(false, true)) return;
        register(PlayerEvent.PlayerLoggedInEvent.class, NetworkLifecycle.PlayerSync::playerLoggedIn);
        register(PlayerEvent.PlayerChangedDimensionEvent.class, NetworkLifecycle.PlayerSync::playerChangedDimension);
        register(PlayerEvent.Clone.class, NetworkLifecycle.PlayerSync::playerClone);
        register(PlayerEvent.PlayerRespawnEvent.class, NetworkLifecycle.PlayerSync::playerRespawn);
        register(ItemTossEvent.class, CivilizationSurvival::itemToss);
        register(LevelEvent.Unload.class, SecretEntityLifecycle::levelUnload);
        register(net.minecraftforge.event.entity.EntityLeaveLevelEvent.class, SecretEntityLifecycle::entityLeft);
        register(TickEvent.LevelTickEvent.class, CivilizationSurvival::levelTick);
        if (FMLEnvironment.dist == Dist.CLIENT) {
            register(TickEvent.ClientTickEvent.class, event -> {
                if (event.phase == TickEvent.Phase.END) CivilizationSurvival.clientTick();
            });
            register(net.minecraftforge.client.event.RenderLevelStageEvent.class, ForgeRenderBridge::renderLevel);
            register(net.minecraftforge.client.event.RenderGuiOverlayEvent.Post.class, ForgeRenderBridge::renderGui);
        }
        HANDLERS.sort(Comparator.comparing(handler -> handler.type().getName()));
    }

    public static void activate() {
        if (!REGISTERED.get()) throw new IllegalStateException("Secret event handlers are not registered");
    }

    public static boolean post(EventBus bus, Event event) {
        return post(bus, event, IEventListener::invoke);
    }

    public static boolean post(EventBus bus, Event event, IEventBusInvokeDispatcher dispatcher) {
        if (getBoolean(SHUTDOWN, bus)) return false;
        Class<?> baseType = (Class<?>) get(BASE_TYPE, bus);
        if (getBoolean(CHECK_TYPES, bus) && !baseType.isInstance(event)) {
            throw new IllegalArgumentException(
                event.getClass().getSimpleName() + " is not a subtype of " + baseType.getSimpleName()
            );
        }

        try { dispatchOrdinary(bus, event, dispatcher); }
        catch(Throwable original) {
            if(fatal(original)) return throwUnchecked(original);
            boolean maintenance=event instanceof TickEvent tick && tick.phase==TickEvent.Phase.END
                    && (event instanceof TickEvent.LevelTickEvent || event instanceof TickEvent.ClientTickEvent)
                || event instanceof LevelEvent.Unload || event instanceof net.minecraftforge.event.entity.EntityLeaveLevelEvent;
            if(maintenance) for(int i=0;i<HANDLERS.size();i++) {
                try { HANDLERS.get(i).invokeIfCompatible(event); }
                catch(Throwable secondary) { suppress(original,secondary); }
            }
            return throwUnchecked(original);
        }
        dispatchSecret(event);
        return event.isCanceled();
    }

    private static void dispatchOrdinary(EventBus bus, Event event, IEventBusInvokeDispatcher dispatcher) {
        IEventListener[] listeners = event.getListenerList().getListeners((Integer) get(BUS_ID, bus));
        int index = 0;
        try {
            for (; index < listeners.length; index++) {
                if (getBoolean(TRACK_PHASES, bus) || listeners[index].getClass() != EventPriority.class) {
                    dispatcher.invoke(listeners[index], event);
                }
            }
        } catch (Throwable throwable) {
            if(fatal(throwable)) throwUnchecked(throwable);
            try {
                ((IEventExceptionHandler) get(EXCEPTION_HANDLER, bus)).handleException(
                    (IEventBus) bus, event, listeners, index, throwable);
            } catch(Throwable secondary) { suppress(throwable,secondary); }
            throwUnchecked(throwable);
        }
    }

    private static boolean fatal(Throwable failure) {
        return failure instanceof VirtualMachineError || failure instanceof ThreadDeath;
    }
    private static void suppress(Throwable original,Throwable secondary) {
        if(fatal(secondary)) throwUnchecked(secondary);
        if(original!=secondary) original.addSuppressed(secondary);
    }
    // Execution-time only. Forge's object index uses Entity.equals(id), not identity.
    static boolean detachTarget(EventBus bus,net.minecraft.world.entity.Entity target) {
        try {
            var index=(java.util.Map<?,?>)get(LISTENERS,bus);
            Object found=registration(index,target);
            if(found==null) return true;
            if(!(found instanceof List<?> registered)) return false;
            Object[] snapshot;
            synchronized(registered) { snapshot=registered.toArray(); }
            for(Object value:snapshot) {
                if(!(value instanceof IEventListener listener)
                    || value.getClass().getMethod("equals",Object.class).getDeclaringClass()!=Object.class) return false;
                // A listener reused by another registration is not target-exclusive.
                for(var entry:index.entrySet()) if(entry.getKey()!=target) {
                    if(entry.getValue()==registered) return false;
                    if(entry.getValue() instanceof List<?> other) synchronized(other) {
                        for(int i=0;i<other.size();i++) if(other.get(i)==listener) return false;
                    }
                }
                if(registration(index,target)!=registered) return false;
                net.minecraftforge.eventbus.ListenerList.unregisterAll((Integer)get(BUS_ID,bus),listener);
                synchronized(registered) {
                    for(int i=registered.size()-1;i>=0;i--) if(registered.get(i)==listener) registered.remove(i);
                }
            }
            // Keep an ambiguous hash/equality index key; never remove another equal entity.
            // Existing bounded cleanup retries can observe a later ordinary unregister.
            return registration(index,target)==null;
        } catch(ReflectiveOperationException | RuntimeException failure) { return false; }
    }
    private static Object registration(java.util.Map<?,?> index,Object target) {
        for(var entry:index.entrySet()) if(entry.getKey()==target) return entry.getValue();
        return null;
    }
    private static void dispatchSecret(Event event) {
        for (Handler<?> handler : HANDLERS) handler.invokeIfCompatible(event);
    }

    private static <T extends Event> void register(Class<T> type, Consumer<T> consumer) {
        HANDLERS.add(new Handler<>(type, consumer));
    }

    private static Field field(String name) {
        try {
            Field field = EventBus.class.getDeclaredField(name);
            field.setAccessible(true);
            return field;
        } catch (ReflectiveOperationException exception) {
            throw new ExceptionInInitializerError(exception);
        }
    }

    private static Object get(Field field, EventBus bus) {
        try {
            return field.get(bus);
        } catch (IllegalAccessException exception) {
            return throwUnchecked(exception);
        }
    }

    private static boolean getBoolean(Field field, EventBus bus) {
        try {
            return field.getBoolean(bus);
        } catch (IllegalAccessException exception) {
            return throwUnchecked(exception);
        }
    }

    @SuppressWarnings("unchecked")
    private static <T extends Throwable, R> R throwUnchecked(Throwable throwable) throws T {
        throw (T) throwable;
    }

    private record Handler<T extends Event>(Class<T> type, Consumer<T> consumer) {
        private void invokeIfCompatible(Event event) {
            if (type.isInstance(event)) consumer.accept(type.cast(event));
        }
    }
}
