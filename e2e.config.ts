import type {E2EConfig} from 'e2e';
import {web} from '@e2e-dev/web';
export default {tests:'tests/browser/**/*.e2e.ts',workers:1,retries:0,trace:'on',timeout:30000,targets:[{name:'chromium',engine:web(),app:{url:'http://127.0.0.1:4190',command:{executable:'node',args:['tests/browser/serve.mjs']}}}]} satisfies E2EConfig;
