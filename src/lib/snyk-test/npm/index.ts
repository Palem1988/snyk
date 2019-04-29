import * as baseDebug from 'debug';
const debug = baseDebug('snyk');
import * as request from '../../request';
import * as fs from 'then-fs';
import * as snyk from '../..';
import * as spinner from '../../spinner';
import * as moduleToObject from 'snyk-module';
import * as isCI from '../../is-ci';
import * as _ from 'lodash';
import * as analytics from '../../analytics';
import * as common from '../common';
import * as detect from '../../detect';
import {getDependenciesFromNodeModules} from './npm-modules-plugin';
import {generateDependenciesFromLockfile} from './npm-lock-plugin';
// import * as depGraphLib from '@snyk/dep-graph';
import {AnnotatedIssue} from '../legacy';

// important: this is different from ./config (which is the *user's* config)
import * as config from '../../config';

export = runTest;

interface Payload {
  method: string;
  url: string;
  json: boolean;
  headers: {
    'x-is-ci': boolean;
    authorization: string;
  };
  body?: {
    // depGraph: depGraphLib.DepGraph,
    policy: string;
    targetFile?: string;
    projectNameOverride?: string;
    hasDevDependencies: boolean;
  };
  qs?: object | null;
  modules?: {
    numDependencies: number;
    pluck: any;
  };
}

async function runTest(root, options): Promise<object> {
  options.packageManager = options.packageManager || detect.detectPackageManager(root, options);
  const lbl = 'Querying vulnerabilities database...';

  const payload: Payload = await assemblePayload(root, options);

  try {

    // const depGraph = payload.body && payload.body.depGraph;
    await spinner(lbl);
    let res = await sendPayload(payload, root, options);
    // if (depGraph) {
    //   res = convertTestDepGraphResultToLegacy(
    //     res,
    //     depGraph,
    //     options.packageManager,
    //     options.severityThreshold);
    // }

    analytics.add('vulns-pre-policy', res.vulnerabilities.length);

    if (!options['ignore-policy']) {
      const policy = await snyk.policy.loadFromText(res.policy);
      res = policy.filter(res, root);
    }
    analytics.add('vulns', res.vulnerabilities.length);

    res.uniqueCount = countUniqueVulns(res.vulnerabilities);

    return res;
  } finally {
    spinner.clear(lbl)();
  }
}

async function assemblePayload(root: string, options): Promise<Payload> {
  // if the file exists, let's read the package files and post
  // the dependency tree to the server.
  // if it doesn't, then we're assuming this is an existing
  // module on npm, so send the bare argument
  const isLocal = await fs.exists(root);
  analytics.add('local', isLocal);
  if (isLocal) {
    return assembleLocalPayload(root, options);
  }
  return assembleRemotePayload(root, options);
}

function assembleRemotePayload(root: string, options): Payload {
  const url = `${config.API}${(options.vulnEndpoint || `/vuln/${options.packageManager}`)}`;
  const module = moduleToObject(root);
  debug('testing remote: %s', module.name + '@' + module.version);

  addPackageAnalytics(module);
  return {
    method: 'GET',
    url: `${url}/${encodeURIComponent(module.name + '@' + module.version)}`,
    qs: common.assembleQueryString(options),
    json: true,
    headers: {
      'x-is-ci': isCI,
      'authorization': 'token ' + snyk.api,
    },
  };
}

async function assembleLocalPayload(root: string, options): Promise<Payload> {
  // options.vulnEndpoint is only used for file system tests
  const url = `${config.API}${(options.vulnEndpoint || `/vuln/${options.packageManager}`)}`;

  let policyLocations: string[] = [options['policy-path'] || root];
  options.file = options.file || detect.detectPackageFile(root);

  const isLockFileBased = (options.file.endsWith('package-lock.json') || options.file.endsWith('yarn.lock'));
  if (options.file.endsWith('yarn.lock') && getRuntimeVersion() < 6) {
    options.traverseNodeModules = true;
  }

  const getLockFileDeps = isLockFileBased && !options.traverseNodeModules;
  const pkg = getLockFileDeps ?
    await generateDependenciesFromLockfile(root, options, options.file) :
    await getDependenciesFromNodeModules(root, options, options.file);

  policyLocations = policyLocations.concat(pluckPolicies(pkg));
  debug('policies found', policyLocations);
  analytics.add('policies', policyLocations.length);

  let policy;
  try {
    // load all relevant policies, apply relevant options
    policy = await snyk.policy.load(policyLocations, options);
    console.log('POLICY: ', JSON.stringify({...pkg, policy}));
  } catch (error) {
    // note: inline catch, to handle error from .load
    // the .snyk file wasn't found, which is fine, so we'll return
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }

  // debug('converting dep-tree to dep-graph', {name: pkg.name, targetFile: pkg.targetFile || options.file});
  // const depGraph = await depGraphLib.legacy.depTreeToGraph(pkg, options.packageManager);
  // debug('done converting dep-tree to dep-graph', {uniquePkgsCount: depGraph.getPkgs().length});

  analytics.add('policies', policyLocations.length);
  addPackageAnalytics(pkg);

  return {
    method: 'POST',
    url,
    qs: common.assembleQueryString(options),
    json: true,
    headers: {
      'x-is-ci': isCI,
      'authorization': 'token ' + snyk.api,
    },
    body: {
      // depGraph,
      ...pkg,
      targetFile: pkg.targetFile || options.file,
      projectNameOverride: options.projectName,
      policy: policy && policy.toString(),
      hasDevDependencies: pkg.hasDevDependencies,
    },
    modules: getLockFileDeps ? undefined : pkg,
  };
}

interface Module {
  name: string;
  version: string;
}

function addPackageAnalytics(module: Module): void {
  analytics.add('packageManager', 'npm');
  analytics.add('packageName', module.name);
  analytics.add('packageVersion', module.version);
  analytics.add('package', module.name + '@' + module.version);
}

async function sendPayload(payload: Payload, root: string, options): Promise<any> {
  const hasDevDependencies = payload && payload.body && payload.body.hasDevDependencies;
  const filesystemPolicy = payload.body && !!payload.body.policy;

  const payloadRes: any = await new Promise((resolve, reject) => {
    request(payload, (error, result, body) => {
      if (error) {
        return reject(error);
      }

      if (result.statusCode !== 200) {
        const err: any = new Error(body && body.error ?
          body.error :
          result.statusCode);

        err.userMessage = body && body.userMessage;
        // this is the case where a local module has been tested, but
        // doesn't have any production deps, but we've noted that they
        // have dep deps, so we'll error with a more useful message
        if (result.statusCode === 404 && hasDevDependencies) {
          err.code = 'NOT_FOUND_HAS_DEV_DEPS';
        } else {
          err.code = result.statusCode;
        }

        if (result.statusCode === 500) {
          debug('Server error', body.stack);
        }

        return reject(err);
      }

      body.filesystemPolicy = filesystemPolicy;

      resolve(body);
    });
  });

  // This branch is valid for node modules flow only
  if (payload.modules) {
    payloadRes.dependencyCount = payload.modules.numDependencies;
    if (payloadRes.vulnerabilities) {
      payloadRes.vulnerabilities.forEach((vuln) => {
        const plucked = payload.modules && payload.modules.pluck(vuln.from, vuln.name, vuln.version);
        vuln.__filename = plucked.__filename;
        vuln.shrinkwrap = plucked.shrinkwrap;
        vuln.bundled = plucked.bundled;

        // this is an edgecase when we're testing the directly vuln pkg
        if (vuln.from.length === 1) {
          return;
        }

        const parentPkg = moduleToObject(vuln.from[1]);
        const parent = payload.modules && payload.modules.pluck(vuln.from.slice(0, 2),
          parentPkg.name,
          parentPkg.version);
        vuln.parentDepType = parent.depType;
      });
    }
  }

  return payloadRes;
}

function countUniqueVulns(vulns: AnnotatedIssue[]): number {
  const seen = {};
  const count = vulns.reduce((acc, curr) => {
    if (!seen[curr.id]) {
      seen[curr.id] = true;
      acc++;
    }
    return acc;
  }, 0);

  return count;
}

function pluckPolicies(pkg) {
  if (!pkg) {
    return null;
  }

  if (pkg.snyk) {
    return pkg.snyk;
  }

  if (!pkg.dependencies) {
    return null;
  }

  return _.flatten(Object.keys(pkg.dependencies).map((name) => {
    return pluckPolicies(pkg.dependencies[name]);
  }).filter(Boolean));
}

function getRuntimeVersion() {
  return parseInt(process.version.slice(1).split('.')[0], 10);
}
