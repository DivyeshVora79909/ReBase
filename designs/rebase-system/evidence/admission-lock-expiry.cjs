const assert = require('node:assert/strict');
const { fork, spawn } = require('node:child_process');
const { once } = require('node:events');
const net = require('node:net');
const path = require('node:path');
const crypto = require('node:crypto');
const repo = process.cwd();
const { createBullMqPort } = require(path.join(repo, 'gateway/queues/bullmq'));
const envelope = name => ({version: 1, kind: 'operation', locator: {namespace:'audit', database:'probe', id:`task:${name}`}, executionId:crypto.randomUUID(), revision:crypto.randomUUID()});
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const options = (url, prefix) => ({url, prefix, admission:{maxLiveHints:2,receiptReserve:0}});
if (process.argv[2] === 'producer') {
  (async()=>{
    const port = createBullMqPort(options(process.argv[3], process.argv[4]));
    const add = port.queue.add.bind(port.queue);
    port.queue.add = async (...args) => {
      process.send({state:'after-final-lock-check'});
      await new Promise(resolve => process.once('message', resolve));
      return add(...args);
    };
    try { process.send({state:'result',result:await port.publish(envelope('stalled'))}); }
    finally {await port.close(); process.disconnect();}
  })().catch(error=>{console.error(error);process.exit(1);});
} else {
  (async()=>{
    const socket = net.createServer();
    await new Promise(resolve=>socket.listen(0,'127.0.0.1',resolve));
    const number = socket.address().port;
    await new Promise(resolve=>socket.close(resolve));
    const redis = spawn('redis-server',['--bind','127.0.0.1','--port',String(number),'--save','','--appendonly','no'],{stdio:'ignore'});
    let port, child;
    try {
      for(let attempt=0;attempt<100;attempt++) {
        const ready=await new Promise(resolve=>{const client=net.createConnection({host:'127.0.0.1',port:number});client.once('connect',()=>{client.destroy();resolve(true);});client.once('error',()=>{client.destroy();resolve(false);});});
        if(ready)break;
        await sleep(20);
      }
      const url=`redis://127.0.0.1:${number}`;
      const prefix=`audit-expiry-${crypto.randomUUID()}`;
      port=createBullMqPort(options(url,prefix));
      child=fork(__filename,['producer',url,prefix],{stdio:['ignore','inherit','inherit','ipc']});
      const first=await once(child,'message');
      assert.equal(first[0].state,'after-final-lock-check');
      child.kill('SIGSTOP');
      const key=`${prefix}:rebase-admission-lock`;
      const ttl=await port.connection.pttl(key);
      assert(ttl>0);
      console.log(JSON.stringify({stage:'paused-after-check',lockTtlMs:ttl}));
      await sleep(ttl+200);
      assert.equal(await port.connection.exists(key),0);
      const b1=await port.publish(envelope('second-1'));
      const b2=await port.publish(envelope('second-2'));
      assert.equal(b1.queued,true);assert.equal(b2.queued,true);
      const result=once(child,'message');
      child.send({resume:true});child.kill('SIGCONT');
      const [message]=await result;
      assert.equal(message.result.queued,true);
      const health=await port.health();
      console.log(JSON.stringify({finding:'live-hint-limit-exceeded-after-real-lock-expiry',maxLiveHints:2,liveHints:health.liveHints,staleProducer:message.result}));
      assert.equal(health.liveHints,3);
      console.log('REPRODUCED: producer resumed after its lease expired and admitted a third live hint above the configured limit of two.');
    } finally {
      if(child && child.exitCode===null && child.signalCode===null){child.kill('SIGCONT');child.kill('SIGTERM');}
      if(port)await port.close();
      const exit=once(redis,'exit');redis.kill('SIGTERM');await exit;
    }
  })().catch(error=>{console.error(error);process.exitCode=1;});
}
