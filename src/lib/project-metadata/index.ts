import * as gitMetadata from './git';
import subProcess = require('../sub-process');
import { GitTarget } from './types';

export async function getInfo(packageInfo): Promise<GitTarget|null> {
  // This is meant to be a factory once we introduce more flavours like Docker for example
  // currently only handles git. The docker is just an example on how to expand it
  if (packageInfo.docker) {
    return null;
  } else if ((await subProcess.execute('git', ['remote', 'get-url', 'origin'])).trim()) {
    return gitMetadata.getInfo();
  }

  return null;
}
