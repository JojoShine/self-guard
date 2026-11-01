function checkLogAssertions(expected,result){
 const patterns=[['match_regex',true],['no_match_regex',false]].filter(([key])=>typeof expected[key]==='string'&&expected[key].length>0);if(!patterns.length)return {present:false,verified:false,failures:[]};
 const logs=result?.diagnosticLog||[];if(result?.diagnosticEnabled!==true||result.diagnosticTruncated||!Array.isArray(logs)||logs.some(line=>typeof line!=='string'))return {present:true,verified:false,failures:[]};const text=logs.join('\n'),failures=[];
 for(const [key,want]of patterns){let regex;try{regex=new RegExp(expected[key])}catch{return {present:true,verified:false,failures:['原始断言正则无法解析']}}if(regex.test(text)!==want)failures.push(key)}return {present:true,verified:true,failures};
}
module.exports={checkLogAssertions};
