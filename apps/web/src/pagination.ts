export const paginationDefaults={
 defaultPageSize:15,
 pageSizeOptions:[15,30,50,100],
 showSizeChanger:true,
 responsive:true,
 showTotal:(total:number)=>`共 ${total} 条`,
};
export function readPageSize(value:unknown){const size=Number(value);return paginationDefaults.pageSizeOptions.includes(size)?size:paginationDefaults.defaultPageSize;}
export function pageWithinTotal(page:number,total:number,pageSize:number){return Math.min(page,Math.max(1,Math.ceil(total/pageSize)));}
