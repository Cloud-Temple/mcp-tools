"""Isolation commune : aucune tâche de relecture du login ne passe d'un test à l'autre."""
import pytest

from src.mcp_tools.storage import files_credentials


@pytest.fixture(autouse=True)
def _reset_credential_refreshers():
    yield
    # Les singletons (lru_cache) gardent leur instance : on oublie la tâche liée à la
    # boucle du test terminé, pour que le suivant reparte d'une lecture neuve.
    for credentials in list(files_credentials._LIVE):
        credentials.reset()
    # Un test qui fait tourner un lifespan laisse l'état « arrêté » posé par son shutdown.
    files_credentials.start_refreshers()
