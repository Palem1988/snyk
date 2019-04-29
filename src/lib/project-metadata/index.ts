import * as gitMetadata from './git';
import { GitInfo } from './types';

export async function getInfo(metadataSource: string, root: string, targetFile: string): Promise<GitInfo|null> {
  switch (metadataSource) {
    case 'git':
      // This is meant to be a factory once we introduce more flavours like Docker for example
      // currently only handles git.
      return gitMetadata.getInfo(root, targetFile);
    default:
      return null;
  }
}
