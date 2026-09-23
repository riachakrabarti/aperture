// Optional local development QA. Requires Playwright and a Chromium executable.
const {chromium}=require('playwright');
const fs=require('fs');
(async()=>{
  const options={headless:true};if(process.env.APERTURE_TEST_CHROMIUM)options.executablePath=process.env.APERTURE_TEST_CHROMIUM;
  const b=await chromium.launch(options);
  const p=await b.newPage({viewport:{width:1440,height:1100}});
  const c=JSON.parse(fs.readFileSync('data/credentials.json'));
  const errors=[],checks=[];p.on('pageerror',e=>errors.push(e.message));
  const result=()=>p.$eval('#actionResult',n=>n.textContent);
  async function exec(agent,tool,args){await p.selectOption('#agent',agent);if(await p.$eval('#tool',n=>n.value)!==tool)await p.selectOption('#tool',tool);if(args)await p.fill('#arguments',JSON.stringify(args));await p.click('#execute');await p.waitForFunction(()=>!document.querySelector('#execute').disabled);return JSON.parse(await result());}
  async function approve(){await p.fill('#reviewerToken',c.reviewer.token);await p.click('#approve');await p.waitForFunction(()=>document.querySelector('#approvalId').value.length>0);}
  function check(name,ok){checks.push({name,passed:!!ok});if(!ok)throw Error('QA failed: '+name);}
  await p.goto('http://127.0.0.1:8080');await p.fill('#operatorToken',c.operator.token);await p.click('#connect');
  await p.waitForSelector('#workspace:not([hidden])');
  for(const prof of ['commercial','federal']){
    await p.click(`.prof[data-profile="${prof}"]`);
    check(prof+': profile switch applied', await p.$eval('#createProfile',n=>n.textContent)===(prof==='federal'?'Federal-adjacent':'Commercial'));
    await p.click('#newWorkflow');await p.waitForFunction(()=>document.querySelector('#workflow').value.length>0);
    check(prof+': restricted read allowed',(await exec('agent-a','crm.read')).status==='completed');
    const dest={destination:prof==='federal'?'partner.example':'outside.example'};
    const denied=await exec('agent-b','external.send',dest);
    check(prof+': send after read denied',!denied.allow);
    await approve();
    const second=JSON.parse(JSON.stringify(await exec('agent-b','external.send',dest)));
    check(prof+': approved send '+(prof==='federal'?'allowed to allowlisted partner':'allowed'),second.status==='completed');
    if(prof==='federal'){
      check('federal: AC-4 evidence attached to denial',denied.controls.includes('AC-4'));
      const out=await exec('agent-b','external.send',{destination:'outside.example'});
      check('federal: non-allowlisted egress denied',out.reasons.includes('egress_destination_not_allowlisted'));
    }
  }
  await p.screenshot({path:'runtime-federal-preview.png',fullPage:true});
  await p.click('.prof[data-profile="commercial"]');await p.screenshot({path:'runtime-commercial-preview.png',fullPage:true});
  await p.click('.nav[data-tab="assurance"]');await p.click('#runTests');await p.waitForFunction(()=>/checks passed/.test(document.querySelector('#assuranceStatus').textContent),null,{timeout:120000});
  check('assurance suite all passed in UI',/^(\d+) of \1 checks passed/.test(await p.$eval('#assuranceStatus',n=>n.textContent)));
  await p.screenshot({path:'assurance-preview.png',fullPage:true});
  await p.click('.nav[data-tab="evidence"]');await p.click('.prof[data-profile="federal"]');await p.click('#verify');await p.waitForFunction(()=>document.querySelector('#verifyResult').textContent.includes('valid'));
  check('evidence chain verifies in UI',(await p.$eval('#verifyResult',n=>n.textContent)).includes('true'));
  check('federal control table populated',(await p.$$('#controls tr')).length>=8);
  await p.screenshot({path:'evidence-federal-preview.png',fullPage:true});
  await p.setViewportSize({width:390,height:900});await p.click('.nav[data-tab="runtime"]');
  const overflow=await p.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth);
  check('mobile: no document-level horizontal overflow',!overflow);
  await p.screenshot({path:'mobile-preview.png',fullPage:false});
  check('no page JavaScript errors',errors.length===0);
  fs.writeFileSync('browser-qa-report.json',JSON.stringify({checks,errors},null,2));
  console.log(checks.map(x=>(x.passed?'PASS  ':'FAIL  ')+x.name).join('\n'));
  await b.close();
})().catch(e=>{console.error(e.message);process.exit(1)});
