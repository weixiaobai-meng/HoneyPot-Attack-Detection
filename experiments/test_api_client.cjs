const assert = require('node:assert/strict');
const {readJson, requestJson} = require('../systemwire2/flask_server/static/js/api_client.js');
async function main() {
    const response = (text, status=200) => new Response(text,{status});
    assert.equal((await readJson(response('{"code":0,"data":{"n":1}}'))).data.n,1);
    await assert.rejects(readJson(response('',502)),/HTTP 502.*空响应/);
    await assert.rejects(readJson(response('<h1>Bad Gateway</h1>',502)),/HTTP 502.*JSON/);
    await assert.rejects(readJson(response('{"code":',200)),/HTTP 200.*JSON/);
    await assert.rejects(readJson(response('{"code":1,"message":"已有任务"}',429)),/HTTP 429.*已有任务/);
    await assert.rejects(readJson({status:200,redirected:true,url:'http://example/manage/login'}),/登录已失效/);
    await assert.rejects(readJson(response('[]')), /格式不正确/);
    let calls=0;
    global.fetch=async()=>{calls++;return response('',502)};
    await assert.rejects(requestJson('/api/analysis/live',{method:'POST'}),/空响应/);
    assert.equal(calls,1,'POST must never be retried automatically');
    let complete;
    global.fetch=()=>new Promise(resolve=>{complete=resolve});
    const pending=requestJson('/api/analysis/live',{method:'POST'});
    await assert.rejects(requestJson('/api/analysis/live/balanced',{method:'POST'}),/重复提交/);
    complete(response('{"code":0,"data":{}}'));
    await pending;
    global.fetch=(_url,{signal})=>new Promise((resolve,reject)=>{
        signal.addEventListener('abort',()=>reject(new DOMException('timeout','AbortError')));
    });
    await assert.rejects(requestJson('/api/analysis/live',{method:'POST',timeoutMs:5}),/任务可能仍在执行/);
    global.fetch=async()=>response('{"code":0,"data":{}}');
    await requestJson('/api/analysis/live',{method:'POST'}); // lock released after timeout
    console.log('PASS: JSON, empty/HTML/truncated responses, login, HTTP errors, no retry, duplicate guard, timeout release');
}
main().catch(error=>{console.error(error);process.exitCode=1});
