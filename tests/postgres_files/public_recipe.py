"""Parcours réel MCP après admission opérateur ; aucun moteur lancé ni cleanup automatique."""
import argparse
import asyncio
import hashlib
import json
import uuid

from scripts.cli.client import MCPClient
from src.mcp_tools.storage.files_credentials import private_text


async def run(args):
    writer=MCPClient(args.url,private_text(args.writer_token_file),timeout=60)
    admin=MCPClient(args.url,private_text(args.admin_token_file),timeout=60)
    denied=MCPClient(args.url,private_text(args.denied_token_file),timeout=60)
    prefix="qualification/"+str(uuid.uuid4())+"/"
    calls=[]
    async def call(client,op,**kwargs):
        result=await client.call_tool("files",{"operation":op,**kwargs})
        # Ne publier ni contenu, hash de token, path physique ou credential dans les preuves.
        calls.append({"operation":op,"operation_id":kwargs.get("operation_id"),
            "status":result.get("status"),"effect_state":result.get("effect_state"),
            "durability_state":result.get("durability_state")})
        return result
    refusal=await call(denied,"list",prefix=prefix)
    assert refusal.get("status")=="error" and "count" not in refusal and "objects" not in refusal
    missing=await call(writer,"read",path=prefix+"absent")
    assert missing.get("effect_state")=="absent"
    ids=[]
    for i in range(3):
        oid=str(uuid.uuid4());ids.append(oid)
        r=await call(writer,"write",path=prefix+str(i),content="preuve-"+str(i),operation_id=oid)
        assert r.get("remote_result")=="confirmed" and r.get("status")=="ok",r
        retry=await call(writer,"write",path=prefix+str(i),content="preuve-"+str(i),operation_id=oid)
        assert retry.get("remote_result")!="confirmed"  # inspection, pas replay ou nouvel ACK
    page=await call(writer,"list",prefix=prefix,max_keys=1)
    seen=[]
    while True:
        assert page.get("status")=="ok"
        seen.extend(r["path"] for r in page["objects"])
        if not page.get("next_cursor"):
            break
        page=await call(writer,"list",prefix=prefix,max_keys=1,cursor=page["next_cursor"])
    assert seen==[prefix+str(i) for i in range(3)]
    batch=await call(writer,"metadata_batch",paths=[prefix+"0",prefix+"absent",prefix+"0"])
    assert batch["count"]==3 and batch["metadata"][0]==batch["metadata"][2]
    assert batch["metadata"][1]["effect_state"]=="absent"
    first=await call(writer,"read",path=prefix+"0",offset=0,limit=2)
    again=await call(writer,"read",path=prefix+"0",offset=2,limit=2,version_id=first["version_id"])
    assert first["sha256"]==again["sha256"]==hashlib.sha256(b"preuve-0").hexdigest()
    concat_id=str(uuid.uuid4())
    r=await call(writer,"concat",path=prefix+"joined",paths=[prefix+"0",prefix+"1"],separator="|",operation_id=concat_id)
    assert r.get("remote_result")=="confirmed"
    joined=await call(writer,"read",path=prefix+"joined")
    assert joined.get("content")=="preuve-0|preuve-1"
    deletion=str(uuid.uuid4())
    r=await call(writer,"delete",path=prefix+"2",operation_id=deletion)
    assert r.get("remote_result")=="confirmed"
    absent=await call(writer,"read",path=prefix+"2")
    assert absent.get("effect_state")=="absent"
    journal=await call(admin,"reconcile",operation_id=ids[0])
    assert journal.get("effect_state")=="present" and journal.get("remote_result")!="confirmed"
    print(json.dumps({"status":"public_flow_observed","prefix":prefix,"operations":ids+[concat_id,deletion],
        "calls":calls,"required_next":"stop/start process, re-read same prefix/IDs; SQL grants/history/quorum; faults/restore/rollback and independent final-state inspection BEFORE cleanup"},indent=2))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--admitted",action="store_true",required=True)
    p.add_argument("--url",required=True)
    for role in ("writer","admin","denied"):
        p.add_argument("--"+role+"-token-file",required=True)
    args=p.parse_args()
    asyncio.run(run(args))


if __name__=="__main__":
    main()
