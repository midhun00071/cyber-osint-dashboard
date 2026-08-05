import inspect

from app.security import bootstrap_admin_cli


def test_bootstrap_has_no_password_argument_environment_or_startup_hook() -> None:
    parser = bootstrap_admin_cli.build_parser()
    destinations = {action.dest for action in parser._actions}
    assert destinations == {"help", "username", "display_name"}
    source = inspect.getsource(bootstrap_admin_cli)
    assert "getpass(" in source
    assert "os.environ" not in source and "PASSWORD" not in source
    assert "func.count(AuthUser.id)" in source
