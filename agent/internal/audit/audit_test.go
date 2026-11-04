package audit

import (
    "os"
    "strings"
    "testing"
)

func TestHashChainDetectsTampering(t *testing.T){
    p:=t.TempDir()+"/audit.jsonl";l:=New(p)
    if err:=l.Write(Record{Actor:"a",Operation:"one",Resource:"r",Outcome:"success"});err!=nil{t.Fatal(err)}
    if err:=l.Write(Record{Actor:"b",Operation:"two",Resource:"r",Outcome:"success"});err!=nil{t.Fatal(err)}
    if v:=Verify(p);!v.OK||v.Records!=2{t.Fatalf("verify failed: %+v",v)}
    b,err:=os.ReadFile(p);if err!=nil{t.Fatal(err)}
    bad:=strings.Replace(string(b),`"actor":"a"`,`"actor":"x"`,1)
    if err:=os.WriteFile(p,[]byte(bad),0640);err!=nil{t.Fatal(err)}
    if v:=Verify(p);v.OK{t.Fatalf("tampering not detected: %+v",v)}
}
