export const databaseOperationNames:Record<string,string>={LOGIN:'连接认证',LOGOUT:'断开连接'};
export const engineNames:Record<string,string>={oracle:'Oracle',mysql:'MySQL',postgresql:'PostgreSQL',sqlserver:'SQL Server',dm:'达梦',kingbase:'金仓',redis:'Redis',vastbase:'海量 Vastbase'};
export const engineOptions=Object.entries(engineNames).map(([value,label])=>({value,label}));
export type DatabaseInstance={id:string;name:string;stableKey:string;engine:string;version?:string;owner:string;business?:string;hostIds:string[];auditSources:{assetId:string;path:string;format:string}[];endpoints:{address:string;port:number}[];archivedAt?:string;updatedAt:string};
export type ClassificationPolicy={categories:string[];levels:{value:number;name:string;criteria:string;riskFloor:string}[];version:number};

export type CategoryNode={title:string;value:string;selectable:boolean;children:CategoryNode[]};
export function categoryTree(categories:string[]):CategoryNode[]{const roots:CategoryNode[]=[],nodes=new Map<string,CategoryNode>();for(const category of categories){let siblings=roots,path='';for(const part of category.split('/')){path=path?path+'/'+part:part;let node=nodes.get(path);if(!node){node={title:part,value:path,selectable:categories.includes(path),children:[]};nodes.set(path,node);siblings.push(node)}siblings=node.children}}return roots;}
