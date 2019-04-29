import fs = require('fs');
import * as path from 'path';
import * as hostedGitInfo from 'hosted-git-info';

import subProcess = require('../sub-process');
import { GitInfo } from './types';

export async function getInfo(root: string, targetFile: string): Promise<GitInfo|null> {
  const originUrl = (await subProcess.execute('git', ['remote', 'get-url', 'origin'])).trim();

  if (!originUrl) {
    return null;
  }

  const branch = (await subProcess.execute('git', ['rev-parse', '--abbrev-ref', 'HEAD'])).trim();
  const commitSha = (await subProcess.execute('git', ['rev-parse', 'HEAD'])).trim();
  const localRoot = (await subProcess.execute('git', ['rev-parse', '--show-toplevel'])).trim();

  const gitRelativeTargetFile = path.relative(localRoot, path.resolve(root, targetFile));
  const hostedGitMetadata = hostedGitInfo.fromUrl(originUrl);

  return {
    repo: hostedGitMetadata.project,
    owner: hostedGitMetadata.user,
    branch,
    commitSha,
    targetFile: gitRelativeTargetFile,
  };
}
