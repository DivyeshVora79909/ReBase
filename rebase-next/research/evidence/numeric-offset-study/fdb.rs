use foundationdb::{Database, KeySelector, RangeOption};
use futures::executor::block_on;
use std::{borrow::Cow, hint::black_box,time::Instant};
fn keys(n:usize)->Vec<Vec<u8>>{let mut x=0x6a09e667f3bcc909u64;let mut v=1000u64;(0..n).map(|_|{x^=x<<13;x^=x>>7;x^=x<<17;v+=1+x%31;let mut k=b"p/".to_vec();k.extend_from_slice(&v.to_be_bytes());k}).collect()}
fn report(n:usize,k:usize,op:&str,mut f:impl FnMut()->(usize,usize)){
 for _ in 0..3{black_box(f());}let mut times=Vec::new();let mut counts=Vec::new();for _ in 0..7{let t=Instant::now();let c=black_box(f());times.push(t.elapsed().as_nanos() as u64);counts.push(c);}assert!(counts.iter().all(|v|*v==counts[0]));let mut s=times.clone();s.sort_unstable();println!("{{\"backend\":\"foundationdb-7.3.77\",\"n\":{n},\"k\":{k},\"op\":\"{op}\",\"median_ns\":{},\"samples_ns\":{:?},\"client_returned_items\":{},\"binding_read_calls\":{},\"server_scanned_items\":null}}",s[3],times,counts[0].0,counts[0].1);
}
fn scan(db:&Database,lo:&[u8],hi:&[u8],limit:usize,expected:Option<&[Vec<u8>]>) -> (usize,usize){block_on(async{
 let tx=db.create_trx().unwrap();let mut opt=RangeOption::from((lo,hi));opt.limit=Some(limit);opt.mode=foundationdb::options::StreamingMode::WantAll;let mut c=0;let mut calls=0;
 loop{calls+=1;let chunk=tx.get_range(&opt,1,false).await.unwrap();for item in &chunk {if let Some(expected)=expected{assert_eq!(item.key(),expected[c].as_slice());assert_eq!(item.value(),(c as u64).to_be_bytes());} c+=1;}let next=opt.next_range(&chunk);match next{Some(next)=>opt=next,None=>break,}}
 assert_eq!(c,limit);(c,calls)
})}
fn main(){let _network=unsafe{foundationdb::boot()};let path=std::env::args().nth(1).unwrap();let db=Database::from_path(&path).unwrap();let lo=b"p/".as_slice();let hi=b"p0".as_slice();
 for n in [10000usize,100000]{let expected=keys(n);
 block_on(async{let tx=db.create_trx().unwrap();tx.clear_range(b"p/",b"r/");tx.commit().await.unwrap();for batch in expected.chunks(1000){let tx=db.create_trx().unwrap();for key in batch{let rank=expected.binary_search(key).unwrap() as u64;tx.set(key,&rank.to_be_bytes());}tx.commit().await.unwrap();}let tx=db.create_trx().unwrap();tx.set(b"q/outside",b"outside");tx.commit().await.unwrap();});
 let checked=scan(&db,lo,hi,n,Some(&expected));assert_eq!(checked.0,n);
 let mut ks=vec![0,100,10000,n-1];ks.sort_unstable();ks.dedup();for k in ks{if k>=n{continue;}let key=expected[k].as_slice();
 report(n,k,"known_key_range_limit_1",||block_on(async{let tx=db.create_trx().unwrap();let mut opt=RangeOption::from((key,hi));opt.limit=Some(1);let rows=tx.get_range(&opt,1,false).await.unwrap();assert_eq!(rows.len(),1);assert_eq!(rows[0].key(),key);assert_eq!(rows[0].value(),(k as u64).to_be_bytes());(1,1)}));
 report(n,k,"native_get_key_offset",||block_on(async{let tx=db.create_trx().unwrap();let sel=KeySelector::new(Cow::Borrowed(lo),false,1+k as i32);let found=tx.get_key(&sel,false).await.unwrap();assert_eq!(found.as_ref(),key);assert!(found.as_ref()<hi);(1,1)}));
 report(n,k,"native_range_offset_limit_1",||block_on(async{let tx=db.create_trx().unwrap();let sel=KeySelector::new(Cow::Borrowed(lo),false,1+k as i32);let mut opt=RangeOption::from((sel,KeySelector::first_greater_or_equal(hi)));opt.limit=Some(1);let rows=tx.get_range(&opt,1,false).await.unwrap();assert_eq!(rows.len(),1);assert_eq!(rows[0].key(),key);assert_eq!(rows[0].value(),(k as u64).to_be_bytes());(1,1)}));
 report(n,k,"client_prefix_scan_to_rank",||scan(&db,lo,hi,k+1,None));
 }
 report(n,0,"prefix_count_client_scan",||scan(&db,lo,hi,n,None));
 block_on(async{let tx=db.create_trx().unwrap();let sel=KeySelector::new(Cow::Borrowed(lo),false,1+n as i32);let found=tx.get_key(&sel,false).await.unwrap();assert_eq!(found.as_ref(),b"q/outside".as_slice());});println!("{{\"correctness\":\"passed\",\"n\":{n},\"prefix_verified_source_keys_and_values\":true,\"offset_n_escapes_prefix\":true}}");
 }
 block_on(async{let tx=db.create_trx().unwrap();tx.clear_range(b"p/",b"r/");tx.commit().await.unwrap();});drop(db);
}
