import {instanceScope} from './database-instances';
import {Body,Controller,Get,Inject,Param,Post,Query,Req,UseGuards} from '@nestjs/common';
import {z} from 'zod';
import {Db} from './db';
import {AuthGuard,allow} from './auth';
import {assetScope,assertGlobal,restricted,resourceWhere} from './scope';
import {parse,text} from './validation';
import {componentPageInput} from './construction-contracts';

const resourceInput=z.enum(['assets','findings','tasks','sites','businesses','database-instances']);
const flag=z.enum(['true','false']).transform(value=>value==='true');
const queryInput=componentPageInput.extend({selected:text.optional(),assetId:z.string().uuid().optional(),kind:z.enum(['RISK','ALERT']).optional(),status:z.string().max(40).optional(),activeOnly:flag.optional(),unbatched:flag.optional()}).strict();
const fields={assets:{id:true,hostname:true,ip:true,business:true,archivedAt:true},findings:{id:true,title:true,kind:true,status:true,assetId:true},tasks:{id:true,title:true,status:true,assetId:true,batchId:true},sites:{id:true,name:true,hostname:true,enabled:true}};
const delegates={assets:'asset',findings:'finding',tasks:'task',sites:'site'} as const;

@Controller('record-options') @UseGuards(AuthGuard)
export class RecordOptionsController{
 constructor(@Inject(Db)private db:Db){}
 @Get(':resource')async list(@Req()req:any,@Param('resource')raw:string,@Query()query:unknown){
  const resource=parse(resourceInput,raw),value=parse(queryInput,query);
  if(resource==='database-instances'){
   const where={AND:[instanceScope(req.user),...(value.selected?[{id:parse(z.string().uuid(),value.selected)}]:[]),...(value.q?[{name:{contains:value.q,mode:'insensitive' as const}}]:[]),...(value.activeOnly?[{archivedAt:null}]:[])]};const[items,total]=await Promise.all([this.db.databaseInstance.findMany({where,select:{id:true,name:true,engine:true,archivedAt:true},orderBy:[{name:'asc'},{id:'asc'}],take:value.selected?1:value.pageSize,skip:value.selected?0:(value.page-1)*value.pageSize}),this.db.databaseInstance.count({where})]);return {items,total};
  }
  if(resource==='businesses'){
   const names=restricted(req.user)?[...new Set([...(req.user.dataScope.businesses||[]),...(await this.db.asset.findMany({where:assetScope(req.user),select:{business:true},distinct:['business']})).map(asset=>asset.business).filter(Boolean)])]:null;
   const where={AND:[...(names?[{name:{in:names as string[]}}]:[]),...(value.q?[{name:{contains:value.q,mode:'insensitive' as const}}]:[]),...(value.selected?[{name:value.selected}]:[])]};
   // A selected historic name can predate stable group registration. Read its
   // actual visible asset without inventing a group or writing during a GET.
   if(value.selected){
    const row=await this.db.businessGroup.findFirst({where});
    if(row)return {items:[{id:row.name,name:row.name,stableId:row.id}],total:1};
    const existing=await this.db.asset.findFirst({where:{AND:[assetScope(req.user),{business:value.selected}]},select:{id:true}});
    return {items:existing?[{id:value.selected,name:value.selected,stableId:null,legacy:true}]:[],total:existing?1:0};
   }
   const [items,total]=await Promise.all([this.db.businessGroup.findMany({where,orderBy:[{name:'asc'},{id:'asc'}],skip:(value.page-1)*value.pageSize,take:value.pageSize}),this.db.businessGroup.count({where})]);
   return {items:items.map(row=>({id:row.name,name:row.name,stableId:row.id})),total};
  }
  if(resource==='sites')assertGlobal(req.user);
  const selected=value.selected?parse(z.string().uuid(),value.selected):undefined;
  const searchFields=resource==='assets'?['hostname','ip']:resource==='sites'?['name','hostname']:['title'];
  const where:any={AND:[await resourceWhere(this.db,req.user,resource),...(selected?[{id:selected}]:[]),...(value.q?[{OR:searchFields.map(name=>({[name]:{contains:value.q,mode:'insensitive'}}))}]:[])]};
  if(resource==='assets'&&value.activeOnly)where.archivedAt=null;
  if(['findings','tasks'].includes(resource)&&value.assetId)where.assetId=value.assetId;
  if(['findings','tasks'].includes(resource)&&value.status)where.status=value.status;
  if(resource==='findings'&&value.kind)where.kind=value.kind;
  if(resource==='tasks'&&value.unbatched)where.batchId=null;
  const delegate:any=this.db[delegates[resource]],order=resource==='assets'?'hostname':resource==='sites'?'name':'title';
  const [items,total]=await Promise.all([delegate.findMany({where,select:fields[resource],orderBy:[{[order]:'asc'},{id:'asc'}],skip:selected?0:(value.page-1)*value.pageSize,take:selected?1:value.pageSize}),delegate.count({where})]);
  return {items,total};
 }
 @Post('businesses')async createBusiness(@Req()req:any,@Body()body:unknown){
  allow(req,['ADMIN','ANALYST']);assertGlobal(req.user);const value=parse(z.object({name:text.max(200)}).strict(),body);
  return this.db.$transaction(async tx=>{const row=await tx.businessGroup.upsert({where:{name:value.name},create:value,update:{}});await tx.audit.create({data:{actor:req.user.email,action:'UPSERT_BUSINESS_GROUP',resource:'business-groups',resourceId:row.id,detail:{name:row.name}}});return {id:row.name,name:row.name,stableId:row.id}});
 }
}
