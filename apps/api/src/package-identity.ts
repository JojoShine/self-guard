// PyPA Names and normalization: compare registry identities, not spellings.
// https://packaging.python.org/en/latest/specifications/name-normalization/
export function canonicalPackageName(ecosystem:string,name:string){
 if(ecosystem!=='PyPI')return name;
 if(!/^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?(?![\s\S])/.test(name))throw Error('Python软件包名称不符合注册表格式');
 return name.toLowerCase().replace(/[-_.]+/g,'-');
}
