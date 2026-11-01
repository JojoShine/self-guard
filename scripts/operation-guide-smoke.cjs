const fs = require('fs');
const assert = require('node:assert/strict');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
(async () => {
  const env = Object.fromEntries(fs.readFileSync('.env','utf8').split('\n').filter(line=>line&&!line.startsWith('#')).map(line=>{const i=line.indexOf('=');return [line.slice(0,i),line.slice(i+1)];}));
  const menu = fs.readFileSync('apps/web/src/main.tsx','utf8').split('const groups:')[1].split('const names')[0];
  const menus = {overview:'工作台',...Object.fromEntries([...menu.matchAll(/\["([^"]+)",\s*"([^"]+)"\]/g)].map(match=>[match[1],match[2]]))};
  const documentSource=fs.readFileSync('apps/web/src/content/operation-guide.md','utf8');
  const moduleChapters={};let chapter='';
  for(const line of documentSource.split('\n')){if(line.startsWith('## '))chapter=line.slice(3);else if(line.startsWith('### '))moduleChapters[line.slice(4)]=chapter;}
  const browser = await chromium.launch({headless:true,channel:'chrome'});
  try {
    const page = await browser.newPage({viewport:{width:1440,height:1080}});
    page.setDefaultTimeout(12000);
    const errors=[],writes=[];page.on('pageerror',error=>errors.push(error.message));
    await page.goto('http://127.0.0.1:5180');
    await page.getByLabel('邮箱').fill(env.ADMIN_EMAIL||'admin@selfguard.local');
    await page.getByLabel('密码',{exact:true}).fill(env.ADMIN_PASSWORD);
    await page.getByRole('button',{name:/登\s*录/}).click();
    await page.getByRole('heading',{name:'工作台',level:1,exact:true}).waitFor();
    await page.route('**/api/**',route=>{
      if(route.request().method()!=='GET'){writes.push(route.request().method()+' '+new URL(route.request().url()).pathname);return route.abort();}
      return route.continue();
    });
    const guide=page.locator('.operation-guide-page'),article=page.getByRole('article',{name:'操作指南正文'});
    async function opened(){
      await page.getByRole('heading',{name:'Self Guard 操作指南',level:1,exact:true}).waitFor();
      assert.equal(await page.locator('.sidebar,.top,.guide-directory,.module-section').count(),0,'Guide must be independent of the system workspace');
      assert.equal(await page.getByRole('menu').count(),0,'Guide has no side menu');
    }
    // Every Markdown module link returns to its actual workspace menu.
    for(const [key,title] of Object.entries(menus)){
      await page.goto('http://127.0.0.1:5180/#'+key);
      await page.getByRole('heading',{name:title,level:1,exact:true}).waitFor();
      await page.getByRole('button',{name:'操作指南',exact:true}).click();
      await opened();
      await article.getByRole('heading',{name:title,level:3,exact:true}).waitFor();
      const before=await page.evaluate(()=>location.hash);
      const expand=page.getByRole('button',{name:'展开'+moduleChapters[title]+'目录',exact:true});if(await expand.count())await expand.click();
      const toc=page.getByRole('navigation',{name:'操作指南目录'}).getByRole('button',{name:title,exact:true}).last();
      await toc.click();assert.equal(await page.evaluate(()=>location.hash),before,'Directory must not change app route');
      assert.equal(await toc.getAttribute('aria-current'),'location');
      const headingTop=await article.getByRole('heading',{name:title,level:3,exact:true}).evaluate(element=>element.getBoundingClientRect().top);assert.ok(headingTop>=72&&headingTop<=150,title+' directory target hidden under header');
      await article.getByRole('link',{name:'前往'+title,exact:true}).click();
      await page.getByRole('heading',{name:title,level:1,exact:true}).waitFor();
      const item=page.locator('.sidebar .ant-menu-item-selected');
      assert.equal(await item.count(),1,'Selected menu count for '+key);
      assert.equal(await item.textContent(),title,'Selected menu for '+key);
    }
    console.log('Passed standalone Markdown for all current modules, working document directory, no system sidebar and correct module destinations.');
    await page.goto('http://127.0.0.1:5180/#assets?q=guide-return&pageSize=30');
    await page.getByRole('heading',{name:'资产列表',level:1,exact:true}).waitFor();
    await page.getByRole('button',{name:'操作指南',exact:true}).click();await opened();
    await page.getByRole('button',{name:'返回系统'}).click();
    await page.getByRole('heading',{name:'资产列表',level:1,exact:true}).waitFor();
    const returned=new URLSearchParams((await page.evaluate(()=>location.hash)).split('?')[1]);
    assert.equal(returned.get('q'),'guide-return');assert.equal(returned.get('pageSize'),'30');
    await page.getByRole('button',{name:'操作指南',exact:true}).click();await opened();
    await page.mouse.move(0,0);await page.waitForTimeout(250);
    const directoryStyles=await page.locator('.guide-toc').evaluate(element=>({background:getComputedStyle(element).backgroundColor,border:getComputedStyle(element).borderTopWidth,links:[...element.querySelectorAll('.guide-toc-link')].map(link=>({selected:link.getAttribute('aria-current')==='location',color:getComputedStyle(link).color,weight:getComputedStyle(link).fontWeight,background:getComputedStyle(link).backgroundColor})),arrows:[...element.querySelectorAll('.guide-toc-toggle')].map(toggle=>getComputedStyle(toggle).color)}));
    assert.equal(directoryStyles.background,'rgba(0, 0, 0, 0)');assert.equal(directoryStyles.border,'0px');
    assert.equal(directoryStyles.links.filter(link=>link.selected).length,1);
    for(const link of directoryStyles.links){if(link.selected){assert.equal(link.color,'rgb(37, 95, 212)');assert.equal(link.weight,'600');assert.equal(link.background,'rgb(237, 243, 255)');}else{assert.ok(['rgb(32, 43, 64)','rgb(101, 113, 135)'].includes(link.color));assert.equal(link.weight,'400');}}
    for(const color of directoryStyles.arrows)assert.equal(color,'rgb(107, 119, 139)');
    const tocSpacing=await page.locator('.guide-toc').evaluate(element=>({
      rows:[...element.querySelectorAll('.guide-toc-group-heading')].map(row=>({toggle:row.querySelector('.guide-toc-toggle').getBoundingClientRect().right,title:row.querySelector('.guide-toc-chapter').getBoundingClientRect().left})),
      chapters:[...element.querySelectorAll('.guide-toc-chapter')].map(link=>({top:parseFloat(getComputedStyle(link).paddingTop),bottom:parseFloat(getComputedStyle(link).paddingBottom),height:link.getBoundingClientRect().height})),
      children:[...element.querySelectorAll('.guide-toc-level-3')].map(link=>({top:parseFloat(getComputedStyle(link).paddingTop),bottom:parseFloat(getComputedStyle(link).paddingBottom)})),
      gaps:[...element.querySelectorAll('.guide-toc-group+.guide-toc-group')].map(group=>parseFloat(getComputedStyle(group).marginTop))
    }));
    for(const row of tocSpacing.rows)assert.ok(row.toggle<row.title,'Disclosure control must precede chapter title');
    for(const chapter of tocSpacing.chapters)assert.ok(chapter.top>=12&&chapter.bottom>=12&&chapter.height>=44,'Chapter vertical spacing');
    for(const child of tocSpacing.children)assert.ok(child.top>=10&&child.bottom>=10,'Subsection vertical spacing');
    for(const gap of tocSpacing.gaps)assert.ok(gap>=12,'Chapter group separation');

    const ordinary=page.locator('.guide-toc-chapter:not([aria-current])').first();await ordinary.hover();await page.waitForTimeout(250);
    const hoverStyle=await ordinary.evaluate(element=>({color:getComputedStyle(element).color,weight:getComputedStyle(element).fontWeight}));assert.equal(hoverStyle.color,'rgb(32, 43, 64)');assert.equal(hoverStyle.weight,'400');
    await page.mouse.move(0,0);
    const contentLink=await article.getByRole('link').first().evaluate(element=>({color:getComputedStyle(element).color,weight:getComputedStyle(element).fontWeight}));assert.equal(contentLink.color,'rgb(37, 95, 212)');assert.equal(contentLink.weight,'600');
    console.log('Passed neutral regular-weight directory, soft blue active background only, subtle left disclosure controls, larger vertical spacing and unchanged document links.');
    assert.ok(await article.locator('table').count()>=7,'Rendered field and state tables');
    const nav=page.getByRole('navigation',{name:'操作指南目录'});
    const stableHeading=await article.getByRole('heading',{name:'修复任务',level:3,exact:true}).elementHandle();
    for(const chapter of ['研判问题与组织事件','执行修复并验证风险消除']){const expand=nav.getByRole('button',{name:'展开'+chapter+'目录',exact:true});if(await expand.count())await expand.click();}
    assert.equal(await nav.getByRole('button',{name:'收起研判问题与组织事件目录',exact:true}).getAttribute('aria-expanded'),'true');
    assert.equal(await nav.getByRole('button',{name:'收起执行修复并验证风险消除目录',exact:true}).getAttribute('aria-expanded'),'true');
    await nav.getByRole('button',{name:'收起研判问题与组织事件目录',exact:true}).click();
    assert.equal(await nav.getByRole('button',{name:'收起执行修复并验证风险消除目录',exact:true}).getAttribute('aria-expanded'),'true');
    await article.getByRole('heading',{name:'修复任务',level:3,exact:true}).evaluate(element=>element.scrollIntoView({block:'start'}));
    await page.waitForFunction(()=>[...document.querySelectorAll('.guide-toc-link')].some(element=>element.textContent==='修复任务'&&element.getAttribute('aria-current')==='location'));
    assert.equal(await stableHeading.evaluate(element=>element.isConnected),true,'Directory updates must preserve Markdown DOM');
    await page.screenshot({path:'.artifacts/operation-guide-task-explanation-1440.png'});
    await nav.getByRole('button',{name:'修复模板',exact:true}).focus();await page.keyboard.press('Enter');
    const keyboardTarget=await article.getByRole('heading',{name:'修复模板',level:3,exact:true}).evaluate(element=>element.getBoundingClientRect().top);assert.ok(keyboardTarget>=72&&keyboardTarget<=150);
    console.log('Passed readable Markdown tables/examples, independent chapter expansion, reading position tracking and keyboard chapter navigation.');
    for(const width of [1920,1440,1024,768,375]){
      await page.setViewportSize({width,height:1080});await page.waitForTimeout(250);
      await page.evaluate(()=>window.scrollTo(0,0));
      const layout=await guide.evaluate(element=>{
        const content=element.querySelector('.guide-markdown'),container=element.querySelector('.guide-document-layout'),toc=element.querySelector('.guide-toc').getBoundingClientRect(),article=content.getBoundingClientRect(),header=element.querySelector('.guide-document-header'),brand=header.querySelector('.brand-lockup').getBoundingClientRect(),button=header.querySelector('button').getBoundingClientRect();
        const bounds=container.getBoundingClientRect();return {tocRight:toc.right,tocBottom:toc.bottom,articleLeft:article.left,articleTop:article.top,articleWidth:bounds.width,outerLeft:bounds.left,outerRight:innerWidth-bounds.right,brandLeft:brand.left,returnRight:button.right,overflow:document.documentElement.scrollWidth-innerWidth,articleOverflow:content.scrollWidth-content.clientWidth,left:parseFloat(getComputedStyle(container).paddingLeft),right:parseFloat(getComputedStyle(container).paddingRight),headerOverflow:header.scrollWidth-header.clientWidth,overlap:brand.right>button.left};
      });
      assert.ok(layout.overflow<=1&&layout.articleOverflow<=1&&layout.headerOverflow<=1&&!layout.overlap,JSON.stringify({width,layout}));
      assert.equal(layout.left,width<=600?12:width<=800?16:32);assert.equal(layout.right,layout.left);
      if(width>800)assert.ok(Math.abs(layout.articleLeft-layout.tocRight-32)<=1,'Left directory/right article gap at '+width);else assert.ok(layout.articleTop>=layout.tocBottom+23,'Stacked directory above article at '+width);
      assert.equal(layout.articleWidth,Math.min(width,1120));assert.ok(Math.abs(layout.outerLeft-layout.outerRight)<=1,'Centered Markdown at '+width);
      assert.ok(Math.abs(layout.brandLeft-layout.outerLeft-layout.left)<=1,'Header/content left alignment at '+width);assert.ok(Math.abs(width-layout.returnRight-layout.outerRight-layout.right)<=1,'Header/content right alignment at '+width);
      const readingStyles=await article.evaluate(element=>({
        paragraphs:[...element.querySelectorAll(':scope>p')].filter(p=>p.previousElementSibling?.tagName!=='H1').map(p=>({font:getComputedStyle(p).fontSize,bottom:getComputedStyle(p).marginBottom})),
        tips:[...element.querySelectorAll('blockquote')].map(tip=>({font:getComputedStyle(tip.querySelector('p')).fontSize,top:parseFloat(getComputedStyle(tip).paddingTop),left:parseFloat(getComputedStyle(tip).paddingLeft),last:getComputedStyle(tip.lastElementChild).marginBottom})),
        tables:[...element.querySelectorAll('.guide-table-wrapper')].map(wrapper=>({focus:wrapper.tabIndex,verticalOverflow:wrapper.scrollHeight-wrapper.clientHeight,top:parseFloat(getComputedStyle(wrapper).marginTop),bottom:parseFloat(getComputedStyle(wrapper).marginBottom),font:getComputedStyle(wrapper.querySelector('td')).fontSize,cellTop:parseFloat(getComputedStyle(wrapper.querySelector('td')).paddingTop),first:parseFloat(getComputedStyle(wrapper.querySelector('td:first-child')).paddingLeft),last:parseFloat(getComputedStyle(wrapper.querySelector('td:last-child')).paddingRight)})),
        blocks:[...element.querySelectorAll('.guide-table-wrapper,blockquote,pre')].map(block=>({before:block.previousElementSibling?block.getBoundingClientRect().top-block.previousElementSibling.getBoundingClientRect().bottom:100,after:block.nextElementSibling?block.nextElementSibling.getBoundingClientRect().top-block.getBoundingClientRect().bottom:100})),
        code:[...element.querySelectorAll('pre')].map(pre=>({focus:pre.tabIndex,padding:parseFloat(getComputedStyle(pre).paddingLeft),font:getComputedStyle(pre).fontSize,top:parseFloat(getComputedStyle(pre).marginTop),bottom:parseFloat(getComputedStyle(pre).marginBottom)}))
      }));
      for(const paragraph of readingStyles.paragraphs){assert.equal(paragraph.font,'14px');assert.equal(paragraph.bottom,'16px');}
      for(const tip of readingStyles.tips){assert.equal(tip.font,'14px');assert.equal(tip.top,width<=600?14:16);assert.equal(tip.left,width<=600?16:20);assert.equal(tip.last,'0px');}
      for(const table of readingStyles.tables){assert.equal(table.focus,0);assert.ok(table.verticalOverflow<=1);assert.equal(table.font,'14px');assert.equal(table.cellTop,12);assert.equal(table.first,width<=800?16:20);assert.equal(table.last,table.first);assert.equal(table.top,24);assert.equal(table.bottom,24);}
      for(const block of readingStyles.blocks)assert.ok(block.before>=15&&block.after>=15,JSON.stringify({width,block}));
      for(const code of readingStyles.code){assert.equal(code.focus,0);assert.equal(code.font,'12px');assert.equal(code.padding,width<=600?16:20);assert.equal(code.top,24);assert.equal(code.bottom,24);}
      if(width===375){const table=article.locator('.guide-table-wrapper').first();await table.focus();await page.keyboard.press('ArrowRight');await page.keyboard.press('ArrowRight');await page.waitForTimeout(200);assert.ok(await table.evaluate(element=>element.scrollLeft)>0,'Narrow table keyboard horizontal scrolling');}
      await article.getByRole('heading',{name:'按现象排查问题',level:2,exact:true}).scrollIntoViewIfNeeded();
      const returnPosition=await page.getByRole('button',{name:'返回系统'}).boundingBox();assert.ok(returnPosition&&returnPosition.y>=0&&returnPosition.y<100,'Sticky return entry at '+width);
    }
    await page.setViewportSize({width:1440,height:1080});await article.evaluate(element=>{element.tabIndex=-1;element.focus({preventScroll:true});});await page.keyboard.press('Home');await page.waitForTimeout(200);await article.evaluate(element=>element.blur());
    await page.screenshot({path:'.artifacts/operation-guide-markdown-1440.png'});
    await article.getByRole('link',{name:'采集与接入',exact:true}).click();
    await page.getByRole('heading',{name:'采集与接入',level:1,exact:true}).waitFor();
    await page.goBack();await opened();await page.reload();await opened();
    await page.getByRole('button',{name:'返回系统'}).click();await page.getByRole('heading',{name:'工作台',level:1,exact:true}).waitFor();
    console.log('Passed unified body/table/tip spacing and typography, keyboard table scrolling, return filters, back/reload and 1920/1440/1024/768/375px reading layouts.');
    // Read-only fixtures reproduce all conditional action sets without changing business records.
    const fixtures={sites:{id:'guide-site',name:'间距验证站点',hostname:'spacing.example.test',upstream:'http://127.0.0.1:8080',enabled:true,mode:'OBSERVE',config:{},version:1},users:{id:'guide-user',name:'间距验证用户',email:'guide@example.test',role:'VIEWER',disabled:false},tasks:{id:'guide-task',title:'间距验证任务',status:'PENDING',template:'FILE_PERMISSION',parameters:{},createdAt:'2026-10-31T00:00:00Z'}};
    await page.route('**/api/**',route=>{
      if(route.request().method()!=='GET')return route.fallback();
      const path=new URL(route.request().url()).pathname.slice(5);
      const [resource,id]=path.split('/');const fixture=fixtures[resource];
      const json=value=>route.fulfill({contentType:'application/json',body:JSON.stringify(value)});
      if(fixture){if(!id)return json({items:[fixture],total:1});if(id===fixture.id&&path.split('/').length===2)return json(fixture);return json({items:[]});}
      if(path.startsWith('audit')||path.startsWith('workflows/'))return json({items:[],findings:[],tasks:[],incidents:[]});
      return route.fallback();
    });
    for(const [resource,fixture] of Object.entries(fixtures)){
      await page.goto('http://127.0.0.1:5180/#'+resource);await page.locator('.data-panel .record-title-link').first().click();
      const drawer=page.locator('.record-drawer');await drawer.waitFor();
      await drawer.getByRole('button',{name:resource==='tasks'?/批\s*准/:'编辑配置',exact:true}).waitFor();
      await page.addStyleTag({content:'.ant-drawer-content-wrapper{transition:none!important;transform:none!important}'});
      for(const width of [1440,768,375]){
        await page.setViewportSize({width,height:1080});await page.waitForTimeout(250);
        const layout=await drawer.locator('.record-actions').evaluate(element=>{
          const controls=[...element.querySelectorAll(':scope>button,:scope>.ant-select')].map(node=>node.getBoundingClientRect());
          const gaps=[];for(let i=1;i<controls.length;i++)if(Math.abs(controls[i].top-controls[i-1].top)<2)gaps.push(controls[i].left-controls[i-1].right);
          return {count:controls.length,gaps,wrappers:element.querySelectorAll('.ant-space-item').length,overflow:element.scrollWidth-element.clientWidth,wrap:getComputedStyle(element).flexWrap};
        });
        assert.ok(layout.count>=2,resource+' missing actions');assert.equal(layout.wrappers,0);assert.equal(layout.wrap,'wrap');assert.ok(layout.overflow<=1);
        for(const gap of layout.gaps)assert.ok(Math.abs(gap-8)<1,`${resource} at ${width}px: ${JSON.stringify(layout)}`);
        if(resource==='sites'&&width===1440)assert.equal(layout.gaps.length,2,'Both site action gaps measured');
      }
      await drawer.locator('.ant-drawer-close').click();await page.setViewportSize({width:1440,height:1080});
    }
    for(const key of ['rule-tools','rollouts','design-system']){
      await page.goto('http://127.0.0.1:5180/#'+key);await page.getByRole('heading',{name:menus[key],level:1,exact:true}).waitFor();
      for(const width of [1024,900,820,801,768,600,480,375]){
        await page.setViewportSize({width,height:1080});await page.waitForTimeout(250);
        const layout=await page.locator('.top').evaluate(element=>{
          const breadcrumb=element.querySelector('.ant-breadcrumb').getBoundingClientRect(),entry=element.querySelector('.guide-entry').getBoundingClientRect();
          return {overflow:element.scrollWidth-element.clientWidth,overlap:breadcrumb.right>entry.left+1};
        });
        assert.ok(layout.overflow<=1&&!layout.overlap,`${key} header at ${width}px: ${JSON.stringify(layout)}`);
      }
    }
    console.log('Passed shared header with long breadcrumbs at 1024/900/820/801/768/600/480/375px.');
    assert.deepEqual(errors,[]);assert.deepEqual(writes,[]);
    console.log('Passed uniform 8px action gaps on site/user/task details at 1440/768/375px, wrapping and no runtime errors; no business writes.');
  } finally {await browser.close();}
})().catch(error=>{console.error(error.stack);process.exit(1);});
