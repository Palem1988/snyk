import fs = require('fs');
import GitUrlParse = require('git-url-parse');

import subProcess = require('../../sub-process');
import { GitTarget } from '../types';

/* tslint:disable:no-unused-variable */
export async function getInfo(packageInfo): Promise<GitTarget|null> {
  const origin = (await subProcess.execute('git', ['remote', 'get-url', 'origin'])).trim();

  if (!origin) {
    return null;
  }

  const parsedOrigin = GitUrlParse(origin);
  const branch = (await subProcess.execute('git', ['rev-parse', '--abbrev-ref', 'HEAD'])).trim();

  return {
    name: parsedOrigin.full_name,
    branch,
  };
}
/* tslint:enable:no-unused-variable */
