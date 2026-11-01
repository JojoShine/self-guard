// Deployment paths are plain path segments, never API routes or encoded URLs.
export function basePath(value:string){if(value!==''&&(!/^(?:\/[A-Za-z0-9_-]+)+$/.test(value)||value.endsWith('/api')))throw new Error('Invalid BASE_PATH');return value;}
export function platformBaseURL(value:string){
 const match=/^https?:\/\/[^/?#]+(\/[^?#]*)?$/.exec(value),u=new URL(value);
 if(!match||!['http:','https:'].includes(u.protocol)||!u.hostname||u.username||u.password||u.search||u.hash)throw new Error('Invalid platform URL');
 const path=(match[1]||'').replace(/\/$/,'');basePath(path);return u.origin+path;
}
export function platformEndpoint(server:string,path:string){return platformBaseURL(server)+path;}
export function validPlatformURL(value:string){try{platformBaseURL(value);return true}catch{return false}}
