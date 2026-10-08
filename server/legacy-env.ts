/** Deployment compatibility: new ARES settings take precedence over older names. */
export function aresEnvironment(input: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const output = { ...input };
  for (const [name, value] of Object.entries(input)) {
    if (name.startsWith("ZEUS_") && output[`ARES_${name.slice(5)}`] === undefined) {
      output[`ARES_${name.slice(5)}`] = value;
    }
  }
  return output;
}
Object.assign(process.env, aresEnvironment(process.env));
