"""Enable ``python -m trace_engine.cli`` as an alias for the ``trace`` script."""

from trace_engine.cli import cli

if __name__ == "__main__":
    cli()
