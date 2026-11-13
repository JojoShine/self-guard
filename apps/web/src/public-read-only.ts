export type ConfigurationUser={role?:string;publicReadOnly?:boolean};
export const isPublicReadOnly=(user?:ConfigurationUser)=>user?.publicReadOnly===true;
export const canViewConfiguration=(user?:ConfigurationUser)=>user?.role==='ADMIN'||isPublicReadOnly(user);
