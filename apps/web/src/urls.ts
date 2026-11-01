const deploymentBase=import.meta.env.BASE_URL||'/';
export const apiURL=(path:string)=>deploymentBase+'api'+path;
export const assetURL=(path:string)=>deploymentBase+path;
export const currentPlatformURL=()=>location.origin+deploymentBase.replace(/\/$/,'');
export function platformURL(value:string){const u=new URL(value);if(!/^https?:\/\/[^/?#]+(?:\/[A-Za-z0-9_-]+)*\/?$/.test(value)||u.username||u.password||u.search||u.hash||u.pathname.replace(/\/$/,'').endsWith('/api'))throw Error('平台接入地址无效');return u.origin+u.pathname.replace(/\/$/,'');}
