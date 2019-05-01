import fs = require('fs');
import * as path from 'path';
import * as hostedGitInfo from 'hosted-git-info';

import subProcess = require('../sub-process');
import { GitTarget } from './types';

export async function getInfo(): Promise<GitTarget|null> {
  const originUrl = (await subProcess.execute('git', ['remote', 'get-url', 'origin'])).trim();

  if (!originUrl) {
    return null;
  }

  const branch = (await subProcess.execute('git', ['rev-parse', '--abbrev-ref', 'HEAD'])).trim();
  const hostedGitMetadata = hostedGitInfo.fromUrl(originUrl);

  return {
    user: hostedGitMetadata.user,
    project: hostedGitMetadata.project,
    branch,
  };
}
