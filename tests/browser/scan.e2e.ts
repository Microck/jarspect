import {test} from '@e2e-dev/web';
import {expect} from 'e2e';
const fixture='tests/fixtures/bytecode/all-capabilities.jar';
for(const width of [1280,390])test(`real offline scan, persisted result and evidence filters at ${width}px`,async({app,browser,screen})=>{
 await browser.setViewport({width,height:1000});
 await app.open('/');
 await browser.locator('#mod-file').setInputFiles(fixture);
 await screen.getByRole('button','Run scan',{exact:true}).click();
 await expect.poll(()=>browser.evaluate(()=>document.querySelector('#status')!.getAttribute('data-state'))).toBe('done');
 const result=await browser.evaluate(async()=>{
  const id=document.querySelector('#scan-id')!.textContent!;
  const response=await fetch(`/scans/${id}`);
  return {status:response.status,data:await response.json(),rendered:document.querySelector('#verdict-label')!.textContent,ai:document.querySelector('#step-ai-verdict')!.getAttribute('data-state')};
 });
 expect(result.status).toBe(200);
 expect(result.data.verdict.method).toBe('heuristic_fallback');
 expect(result.rendered).toBe(result.data.verdict.result);
 expect(result.ai).toBe('skip');
 expect(result.data.intake.class_file_count).toBeGreaterThan(0);
 const all=await browser.evaluate(()=>document.querySelectorAll('#indicators > li').length);
 expect(all).toBeGreaterThan(1);
 await browser.locator('#indicator-filters button[data-cat]:not([data-cat="all"])').first().click();
 const selected=await browser.evaluate(()=>({count:document.querySelectorAll('#indicators > li').length,label:document.querySelector('#indicator-filters .active')!.textContent}));
 expect(selected.count).toBe(Number(selected.label!.match(/\((\d+)\)/)![1]));
 await browser.locator('#indicator-filters button[data-cat="all"]').click();
 expect(await browser.evaluate(()=>document.querySelectorAll('#indicators > li').length)).toBe(all);
});

test('busy upload cannot be replaced and an earlier scan cannot hide the next pipeline',async({app,browser,screen})=>{
 await app.open('/');
 await browser.locator('#mod-file').setInputFiles(fixture);
 await screen.getByRole('button','Run scan',{exact:true}).click();
 const busy=await browser.evaluate(()=>{
  const input=document.querySelector('#mod-file') as HTMLInputElement;
  const transfer=new DataTransfer();transfer.items.add(new File(['bad'],'replacement.jar'));
  document.querySelector('#drop-zone')!.dispatchEvent(new DragEvent('drop',{bubbles:true,cancelable:true,dataTransfer:transfer}));
  input.dispatchEvent(new Event('change',{bubbles:true}));
  return {disabled:input.disabled,submit:(document.querySelector('#run-scan') as HTMLButtonElement).disabled,name:input.files![0].name};
 });
 expect(busy).toEqual({disabled:true,submit:true,name:'all-capabilities.jar'});
 await expect.poll(()=>browser.evaluate(()=>document.querySelector('#status')!.getAttribute('data-state'))).toBe('done');
 const first=await browser.evaluate(()=>document.querySelector('#scan-id')!.textContent);
 await screen.getByRole('button','Run scan',{exact:true}).click();
 await expect.poll(()=>browser.evaluate(()=>document.querySelector('#status')!.getAttribute('data-state'))).toBe('done');
 const second=await browser.evaluate(()=>({id:document.querySelector('#scan-id')!.textContent,hidden:(document.querySelector('#pipeline-steps') as HTMLElement).hidden}));
 expect(second.id).not.toBe(first);
 expect(second.hidden).toBe(false);
 await expect.poll(()=>browser.evaluate(()=>(document.querySelector('#pipeline-steps') as HTMLElement).hidden)).toBe(true);
});

test('unsupported upload reports a real backend error and recovers',async({app,browser,screen})=>{
 await app.open('/');
 await browser.evaluate(()=>{
  const transfer=new DataTransfer();transfer.items.add(new File(['invalid zip'],'broken.txt'));
  const input=document.querySelector('#mod-file') as HTMLInputElement;input.files=transfer.files;input.dispatchEvent(new Event('change',{bubbles:true}));
  return null;
 });
 await screen.getByRole('button','Run scan',{exact:true}).click();
 await expect.poll(()=>browser.evaluate(()=>document.querySelector('#status')!.getAttribute('data-state'))).toBe('error');
 expect(await browser.evaluate(()=>(document.querySelector('#mod-file') as HTMLInputElement).disabled)).toBe(false);
 await browser.locator('#mod-file').setInputFiles(fixture);
 await screen.getByRole('button','Run scan',{exact:true}).click();
 await expect.poll(()=>browser.evaluate(()=>document.querySelector('#status')!.getAttribute('data-state'))).toBe('done');
});

test('reused escaping node preserves the original browser escaping semantics',async({app,browser})=>{
 await app.open('/');
 const result=await browser.evaluate(()=>{
  const escape=(window as unknown as {escapeHtml:(v:unknown)=>string}).escapeHtml;
  const values=['<script>alert(1)</script>','& < > " \'','é🦆',null,undefined,0,false,''];
  return values.map(value=>{const reference=document.createElement('div');reference.textContent=value as string;return [escape(value),reference.innerHTML];});
 });
 for(const [actual,expected] of result)expect(actual).toBe(expected);
});

test('malformed JAR exposes partial analysis without claiming AI completed',async({app,browser,screen})=>{
 await app.open('/');
 await browser.evaluate(()=>{
  const transfer=new DataTransfer();transfer.items.add(new File(['invalid zip'],'broken.jar'));
  const input=document.querySelector('#mod-file') as HTMLInputElement;input.files=transfer.files;input.dispatchEvent(new Event('change',{bubbles:true}));return null;
 });
 await screen.getByRole('button','Run scan',{exact:true}).click();
 await expect.poll(()=>browser.evaluate(()=>document.querySelector('#status')!.getAttribute('data-state'))).toBe('done');
 const state=await browser.evaluate(()=>({method:document.querySelector('#verdict-method')!.textContent,explanation:document.querySelector('#explanation')!.textContent,ai:document.querySelector('#step-ai-verdict')!.getAttribute('data-state')}));
 expect(state.method).toBe('archive validation failure');
 expect(state.explanation).toContain('could not be fully analyzed');
 expect(state.ai).toBe('skip');
 expect(await browser.evaluate(()=>document.querySelector('#step-ai-verdict .pipeline-step-detail')!.textContent)).toBe('AI skipped -- archive validation failed');
});
