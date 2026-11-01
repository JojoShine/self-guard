// Dedicated acceptance worker; never runs against a business schema.
import 'reflect-metadata';import {Db} from '../src/db';import {Platform} from '../src/platform';import {processActiveScans} from '../src/active-scans';
const url=new URL(process.env.DATABASE_URL||'');if(!/^active_process_[a-f0-9]{16}$/.test(url.searchParams.get('schema')||''))throw Error('Owned process acceptance schema required');
const db=new Db();processActiveScans(db,new Platform(db)).then(()=>console.log('OWNED_WORKER_FINISHED')).catch(error=>{console.error(error.message);process.exitCode=1}).finally(()=>db.$disconnect());
