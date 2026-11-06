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

        dispatchOrdinary(bus, event, dispatcher);
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
            ((IEventExceptionHandler) get(EXCEPTION_HANDLER, bus)).handleException(
                (IEventBus) bus, event, listeners, index, throwable
            );
            throwUnchecked(throwable);
        }
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
