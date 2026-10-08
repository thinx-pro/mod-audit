// Destructured nouns must still be found.
export async function helper(api) {
  const { process: proc } = api
  return proc.run({ argv: ['uname'] })
}
