import { openFdbEnvironment } from '/workspace/ReBase/rebase-next/tools/node/infra.mjs';
import { writeFile, open, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
const scratch='/tmp/rebase-order-study';
const sdk='/workspace/ReBase/rebase-next/target/g7-environment';
const env={PATH:'/usr/bin:/bin',LD_LIBRARY_PATH:`${sdk}/lib`,HOME:'/tmp/rebase-order-study'};
const clusterFile=`${scratch}/fdb.cluster`;
await writeFile(clusterFile,'order_study:orderstudy@127.0.0.1:49481\n');
const owner=await openFdbEnvironment({fdbserver:`${sdk}/upgrade-7.3.77/usr/sbin/fdbserver`,fdbcli:`${sdk}/upgrade-7.3.77/usr/bin/fdbcli`,clusterFile,dataDirectory:`${scratch}/fdb-data`,logDirectory:`${scratch}/fdb-logs`,serverLog:`${scratch}/fdb-server.log`,port:49481,environment:env,startTimeoutMs:20000,commandTimeoutMs:60000});
let child;
try {
 console.log(await owner.start());console.log(await owner.bootstrap());console.log(await owner.check());
 const stdout=await open(`${scratch}/fdb.jsonl`,'w');const stderr=await open(`${scratch}/fdb-stderr.log`,'w');
 try {
 child=spawn(`${scratch}/fdb`,[clusterFile],{env,stdio:['ignore',stdout.fd,stderr.fd]});
 await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{child.kill('SIGTERM');reject(new Error('native trial exceeded180s'));},180000);child.on('error',e=>{clearTimeout(timer);reject(e);});child.on('close',(code,signal)=>{clearTimeout(timer);code===0?resolve():reject(new Error(`native exited${code}/${signal}`));});});
 } finally {await stdout.close();await stderr.close();}
} finally {if(child&&child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');console.log(await owner.close());await rm(`${scratch}/fdb-data`,{recursive:true,force:true});await rm(`${scratch}/fdb-logs`,{recursive:true,force:true});}
