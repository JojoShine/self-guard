const fs=require('fs');
const assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const env=Object.fromEntries(fs.readFileSync('.env','utf8').split('\n').filter(line=>line&&!line.startsWith('#')).map(line=>{const i=line.indexOf('=');return[line.slice(0,i),line.slice(i+1)];}));
 const browser=await chromium.launch({headless:true,channel:'chrome'});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1080}});page.setDefaultTimeout(10000);
  const errors=[],writes=[];page.on('pageerror',error=>errors.push(error.message));
  await page.goto('http://127.0.0.1:5180');await page.getByLabel('邮箱').fill(env.ADMIN_EMAIL||'admin@selfguard.local');await page.getByLabel('密码',{exact:true}).fill(env.ADMIN_PASSWORD);await page.getByRole('button',{name:/登\s*录/}).click();
  await page.getByRole('heading',{name:'工作台',level:1,exact:true}).waitFor();
  await page.route('**/api/**',route=>{if(route.request().method()!=='GET'){writes.push(route.request().method()+' '+new URL(route.request().url()).pathname);return route.abort();}return route.continue();});
  await page.getByRole('button',{name:'操作指南',exact:true}).click();await page.getByRole('heading',{name:'Self Guard 操作指南',level:1,exact:true}).waitFor();
  const nav=page.getByRole('navigation',{name:'操作指南目录'}),article=page.getByRole('article',{name:'操作指南正文'});
  const last='列表、看板和报告数量不同',beforeLast='WAF保存了配置但没有预期效果';
  async function selection(){return page.locator('.guide-toc-link[aria-current=location]').textContent();}
  async function expand(title){const button=nav.getByRole('button',{name:'展开'+title+'目录',exact:true});if(await button.count())await button.click();}
  for(const [width,height] of [[1920,1080],[1440,900],[1366,768],[1280,720],[1024,768],[801,600],[768,1024],[375,812]]){
   await page.setViewportSize({width,height});await expand('按现象排查问题');
   for(const title of [last,beforeLast,'任务显示结果待确认',last]){
    await nav.getByRole('button',{name:'理解系统中的安全对象',exact:true}).click();
    await page.evaluate(()=>{window.__sgGuideSelectionTrace=[];window.__sgGuideSelectionObserver=new MutationObserver(()=>{const selected=document.querySelector('.guide-toc-link[aria-current=location]')?.textContent;if(selected&&window.__sgGuideSelectionTrace.at(-1)!==selected)window.__sgGuideSelectionTrace.push(selected);});window.__sgGuideSelectionObserver.observe(document.querySelector('.guide-toc'),{attributes:true,subtree:true,attributeFilter:['aria-current']});});
    await nav.getByRole('button',{name:title,exact:true}).click();
    await page.waitForTimeout(500);
    const snapshot=await page.evaluate(title=>({selected:document.querySelector('.guide-toc-link[aria-current=location]')?.textContent,headingTop:[...document.querySelectorAll('.guide-markdown h3')].find(element=>element.textContent===title).getBoundingClientRect().top,bottom:Math.abs(scrollY+innerHeight-document.documentElement.scrollHeight)<2}),title);
    const trace=await page.evaluate(()=>{window.__sgGuideSelectionObserver.disconnect();return window.__sgGuideSelectionTrace;});assert.deepEqual(trace,[title],`Secondary selection at ${width}x${height}: ${JSON.stringify(trace)}`);
    assert.equal(snapshot.selected,title,`Clicked directory target was overwritten at ${width}px: ${JSON.stringify(snapshot)}`);
    assert.equal(await page.locator('.guide-toc-link[aria-current=location]').count(),1);
   }
   console.log(`Passed a single stable selection for bottom sections at ${width}x${height}.`);
  }
  await page.setViewportSize({width:1440,height:1080});
  await nav.getByRole('button',{name:last,exact:true}).click();await page.waitForTimeout(300);
  const scroll=page.locator('.guide-toc-scroll'),bodyScroll=await page.evaluate(()=>scrollY);await scroll.evaluate(element=>{element.scrollTop=0;});await scroll.hover();await page.mouse.wheel(0,-10000);await page.waitForTimeout(300);assert.equal(await page.evaluate(()=>scrollY),bodyScroll,'Directory top overscroll moved document');await scroll.evaluate(element=>{element.scrollTop=element.scrollHeight;});await page.mouse.wheel(0,10000);await page.waitForTimeout(300);assert.equal(await page.evaluate(()=>scrollY),bodyScroll,'Directory bottom overscroll moved document');assert.equal(await selection(),last,'Directory-only scrolling changed content selection');
  const body=await article.boundingBox();await page.mouse.move(body.x+body.width-40,500);await page.mouse.wheel(0,-1000);
  await page.waitForFunction(last=>document.querySelector('.guide-toc-link[aria-current=location]')?.textContent!==last,last);
  await page.mouse.wheel(0,10000);await page.waitForTimeout(300);assert.equal(await selection(),last,'Manual reading at document end should select the final section');
  const target=nav.getByRole('button',{name:beforeLast,exact:true});await target.focus();await page.keyboard.press('Enter');await page.waitForTimeout(400);assert.equal(await selection(),beforeLast,'Keyboard navigation was overwritten at bottom');
  await page.locator('.guide-markdown').evaluate(element=>{element.setAttribute('tabindex','-1');element.focus({preventScroll:true});});
  await page.keyboard.press('Home');await page.waitForTimeout(300);assert.equal(await selection(),'理解系统中的安全对象','Keyboard manual scrolling did not resume position tracking');
  await page.keyboard.press('End');await page.waitForTimeout(300);assert.equal(await selection(),last);
  await nav.getByRole('button',{name:beforeLast,exact:true}).click();await page.waitForTimeout(300);
  await page.setViewportSize({width:768,height:900});await page.waitForTimeout(300);assert.equal(await selection(),beforeLast,'Relayout overwrote explicit navigation');
  assert.deepEqual(errors,[]);assert.deepEqual(writes,[]);
  console.log('Passed directory-only scroll isolation, manual wheel/keyboard tracking, bottom detection, keyboard chapter navigation and resize stability; no business writes.');
 }finally{await browser.close();}
})().catch(error=>{console.error(error.stack);process.exit(1);});
