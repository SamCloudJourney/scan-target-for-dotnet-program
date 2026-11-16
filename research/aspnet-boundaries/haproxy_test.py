#!/usr/bin/env python3
"""Loopback-only HAProxy fixture. Record real proxy policy and Kestrel routing outcomes."""
import argparse
import http.client
import json

PORT=5092
HOST="127.0.0.1"
def request(target, host="127.0.0.1:5092"):
    connection=http.client.HTTPConnection(HOST,PORT,timeout=8)
    connection.putrequest("GET",target,skip_host=True,skip_accept_encoding=True)
    connection.putheader("Host",host)
    connection.putheader("Connection","close")
    connection.endheaders()
    response=connection.getresponse()
    result={"target":target,"host":host,"status":response.status,
            "body":response.read().decode("utf-8","replace"),
            "server":response.getheader("Server"),
            "location":response.getheader("Location")}
    connection.close()
    return result

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--major",type=int,choices=(10,11),required=True)
    p.add_argument("--out",required=True)
    a=p.parse_args()
    cases={
        "canonical":request("/gate/secret"),
        "encoded_origin":request("/gate%2Fsecret"),
        "absolute_frontend":request("http://127.0.0.1:5092/gate%2Fsecret"),
        "absolute_backend_authority":request("http://127.0.0.1:5089/gate%2Fsecret","127.0.0.1:5089"),
        "auth_absolute":request("http://127.0.0.1:5092/auth%2Fsecret")
    }
    # The test deliberately permits either backend route result: it measures
    # whether real HAProxy forwards absolute-form bytes or rewrites them.
    checks={"canonical_protected":cases["canonical"]["status"]==403,
            "healthy_backend":cases["encoded_origin"]["status"] in (200,404),
            "auth_no_unauthorized_success":cases["auth_absolute"]["status"]!=200}
    data={"framework":f"net{a.major}.0","proxy":"HAProxy","acl":"path_beg /gate/",
          "cases":cases,"checks":checks,
          "interpretation":"200 on absolute encoded would demonstrate this particular HAProxy rule is insufficient; 404/403 would mean this HAProxy deployment neutralizes the demo."}
    with open(a.out,"w") as f:json.dump(data,f,indent=2)
    print(json.dumps(data,indent=2))
    return int(not all(checks.values()))
if __name__=="__main__":
    raise SystemExit(main())
