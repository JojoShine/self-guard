export function statusOptions(resource:string,kind:string,status:string):string[]{
 const transitions:Record<string,Record<string,string[]>>={
  RISK:{OPEN:['CONFIRMED','IN_PROGRESS','ACCEPTED','FALSE_POSITIVE'],CONFIRMED:['IN_PROGRESS','ACCEPTED','FALSE_POSITIVE'],IN_PROGRESS:['VERIFYING','ACCEPTED','FALSE_POSITIVE'],VERIFYING:['IN_PROGRESS'],CLOSED:['OPEN'],ACCEPTED:['OPEN'],FALSE_POSITIVE:['OPEN']},
  ALERT:{OPEN:['IN_PROGRESS','RESOLVED','FALSE_POSITIVE'],IN_PROGRESS:['RESOLVED','FALSE_POSITIVE'],RESOLVED:['OPEN'],FALSE_POSITIVE:['OPEN']},
  incidents:{OPEN:['IN_PROGRESS'],IN_PROGRESS:['VERIFYING'],VERIFYING:['CLOSED','IN_PROGRESS'],CLOSED:['OPEN']},
 };
 return transitions[resource==='incidents'?'incidents':kind]?.[status]||[];
}
