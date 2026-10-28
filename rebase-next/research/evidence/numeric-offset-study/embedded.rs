use redb::{Database, ReadableDatabase, ReadableTableMetadata, TableDefinition};
use surrealkv::{TreeBuilder, LSMIterator};
use std::{hint::black_box, time::Instant};
const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("ordered");
fn keys(n:usize)->Vec<Vec<u8>> {
 let mut x=0x6a09e667f3bcc909u64; let mut v=1000u64;
 (0..n).map(|_| {x^=x<<13;x^=x>>7;x^=x<<17;v+=1+(x%31);let mut k=b"p/".to_vec();k.extend_from_slice(&v.to_be_bytes());k}).collect()
}
fn report(backend:&str,n:usize,k:usize,op:&str,examined:usize,mut f:impl FnMut()->u64){
 for _ in 0..3{black_box(f());}
 let mut times=Vec::new(); for _ in 0..7{let t=Instant::now();black_box(f());times.push(t.elapsed().as_nanos() as u64);}
 let mut sorted=times.clone();sorted.sort_unstable();
 println!("{{\"backend\":\"{backend}\",\"n\":{n},\"k\":{k},\"op\":\"{op}\",\"client_visible_items_examined\":{examined},\"median_ns\":{},\"samples_ns\":{:?}}}",sorted[3],times);
}
fn main(){
 let rt=tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
 let _guard=rt.enter();
 for n in [10000usize,100000]{
 let expected=keys(n);let lo=b"p/".as_slice();let hi=b"p0".as_slice();
 let path=format!("/tmp/rebase-order-study/redb-{n}");let db=Database::create(&path).unwrap();
 {let tx=db.begin_write().unwrap();{let mut t=tx.open_table(TABLE).unwrap();for (rank,key) in expected.iter().enumerate(){t.insert(key.as_slice(),(rank as u64).to_be_bytes().as_slice()).unwrap();}t.insert(b"q/outside".as_slice(),b"outside".as_slice()).unwrap();}tx.commit().unwrap();}
 {let tx=db.begin_read().unwrap();let t=tx.open_table(TABLE).unwrap();let found:Vec<_>=t.range(lo..hi).unwrap().map(|v|v.unwrap().0.value().to_vec()).collect();assert_eq!(found,expected);assert_eq!(t.len().unwrap(),n as u64+1);}
 let spath=format!("/tmp/rebase-order-study/surreal-{n}");
 {let tree=TreeBuilder::new().with_path(spath.clone().into()).build().unwrap();let mut tx=tree.begin().unwrap();for (rank,key) in expected.iter().enumerate(){tx.set(key.as_slice(),(rank as u64).to_be_bytes().as_slice()).unwrap();}tx.set(b"q/outside".as_slice(),b"outside".as_slice()).unwrap();rt.block_on(tx.commit()).unwrap();rt.block_on(tree.close()).unwrap();}
 let tree=TreeBuilder::new().with_path(spath.clone().into()).build().unwrap();
 {let tx=tree.begin().unwrap();let mut iter=tx.range(lo,hi).unwrap();iter.seek_first().unwrap();let mut idx=0;while iter.valid(){assert_eq!(iter.key().user_key(),expected[idx].as_slice());assert_eq!(iter.value().unwrap().as_slice(),(idx as u64).to_be_bytes().as_slice());idx+=1;iter.next().unwrap();}assert_eq!(idx,n);}
 let mut ranks=vec![0,100,10000,n-1];ranks.sort_unstable();ranks.dedup();
 for k in ranks{if k>=n{continue;}let key=expected[k].as_slice();
 report("redb-4.4.0",n,k,"key_seek",1,||{let tx=db.begin_read().unwrap();let t=tx.open_table(TABLE).unwrap();let (a,b)=t.range(key..hi).unwrap().next().unwrap().unwrap();assert_eq!(a.value(),key);assert_eq!(b.value(),(k as u64).to_be_bytes());k as u64});
 report("redb-4.4.0",n,k,"ordinal_iterate",k+1,||{let tx=db.begin_read().unwrap();let t=tx.open_table(TABLE).unwrap();let mut it=t.range(lo..hi).unwrap();for _ in 0..k{black_box(it.next().unwrap().unwrap());}let (a,b)=it.next().unwrap().unwrap();assert_eq!(a.value(),key);assert_eq!(b.value(),(k as u64).to_be_bytes());k as u64});
 report("surrealkv-1.0.0",n,k,"key_seek",1,||{let tx=tree.begin().unwrap();let mut it=tx.range(lo,hi).unwrap();it.seek(key).unwrap();assert!(it.valid());assert_eq!(it.key().user_key(),key);assert_eq!(it.value().unwrap().as_slice(),(k as u64).to_be_bytes().as_slice());k as u64});
 report("surrealkv-1.0.0",n,k,"ordinal_iterate",k+1,||{let tx=tree.begin().unwrap();let mut it=tx.range(lo,hi).unwrap();it.seek_first().unwrap();for _ in 0..k{black_box(it.key());it.next().unwrap();}assert!(it.valid());assert_eq!(it.key().user_key(),key);assert_eq!(it.value().unwrap().as_slice(),(k as u64).to_be_bytes().as_slice());k as u64});
 }
 report("redb-4.4.0",n,0,"whole_table_len_includes_outside_prefix",0,||{let tx=db.begin_read().unwrap();let t=tx.open_table(TABLE).unwrap();let c=t.len().unwrap();assert_eq!(c,n as u64+1);c});
 report("redb-4.4.0",n,0,"prefix_count_iterate",n,||{let tx=db.begin_read().unwrap();let t=tx.open_table(TABLE).unwrap();let c=t.range(lo..hi).unwrap().map(|r|r.unwrap()).count() as u64;assert_eq!(c,n as u64);c});
 report("surrealkv-1.0.0",n,0,"prefix_count_iterate",n,||{let tx=tree.begin().unwrap();let mut it=tx.range(lo,hi).unwrap();it.seek_first().unwrap();let mut c=0;while it.valid(){black_box(it.key());c+=1;it.next().unwrap();}assert_eq!(c,n as u64);c});
 println!("{{\"correctness\":\"passed\",\"n\":{n},\"first_numeric_key\":{},\"last_numeric_key\":{},\"rank_100_numeric_key\":{},\"numeric_key_not_rank\":true,\"outside_prefix_entries\":1,\"surrealkv_reopened_after_flush_on_close\":true}}",u64::from_be_bytes(expected[0][2..].try_into().unwrap()),u64::from_be_bytes(expected[n-1][2..].try_into().unwrap()),u64::from_be_bytes(expected[100][2..].try_into().unwrap()));
 rt.block_on(tree.close()).unwrap();drop(tree);drop(db);std::fs::remove_file(path).unwrap();std::fs::remove_dir_all(spath).unwrap();
 }
}
