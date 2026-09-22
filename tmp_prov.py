from horcrux.intel.provisioning import discover_auth_surfaces
from horcrux.models import WorkspaceState
from horcrux.modules.web.security_validators import httpx_request_fn

st = WorkspaceState.model_validate_json(
    open("workspaces/127.0.0.1_3000/state.json", encoding="utf-8").read())
app = st.get_application_model()
surfaces = discover_auth_surfaces(app)
print("reg:", surfaces["register"][:5])
print("login:", surfaces["login"][:5])


def req(method, url, query=None, body=None, headers=None, **kw):
    return httpx_request_fn(method, url, query=query, body=body,
                            headers=headers)


r = req("POST", "http://127.0.0.1:3000/api/Users",
        body={"email": "hxq@horcrux.test", "username": "hxbq",
              "password": "Hx-test1!"})
print("register:", r.get("status"), r.get("text", "")[:150])
