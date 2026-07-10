from aiogram import Dispatcher

from app.bot.main import create_dispatcher


def test_create_dispatcher_returns_dispatcher():
    dispatcher = create_dispatcher()

    assert isinstance(dispatcher, Dispatcher)


def test_create_dispatcher_accepts_workflow_dependency():
    dispatcher = create_dispatcher(workflow=object())

    assert isinstance(dispatcher, Dispatcher)
    assert dispatcher["workflow"] is not None


def test_create_dispatcher_registers_admin_traffic_callback():
    dispatcher = create_dispatcher(workflow=object())
    router = dispatcher.sub_routers[0]

    callback_names = {
        handler.callback.__name__ for handler in router.callback_query.handlers
    }

    assert "admin_traffic" in callback_names


def test_create_dispatcher_registers_admin_servers_callback():
    dispatcher = create_dispatcher(workflow=object())
    router = dispatcher.sub_routers[0]

    callback_names = {
        handler.callback.__name__ for handler in router.callback_query.handlers
    }

    assert "admin_servers" in callback_names


def test_create_dispatcher_registers_admin_integrations_callback():
    dispatcher = create_dispatcher(workflow=object())
    router = dispatcher.sub_routers[0]

    callback_names = {
        handler.callback.__name__ for handler in router.callback_query.handlers
    }

    assert "admin_integrations" in callback_names
