import { BskyAgent } from '@atproto/api'
/*
import { PGlite } from "@electric-sql/pglite";
import { live } from '@electric-sql/pglite/live';
import { lo } from '@electric-sql/pglite/contrib/lo';

const pg = new PGlite(
  "./my-pgdata",
  {
    extensions: { live, lo }
  },
);

await db.query("select 'Hello world' as message;")
*/

const agent = new BskyAgent({
  service: Deno.env.get("ATPROTO_BASE_URL"),
})
await agent.login({
  identifier: Deno.env.get("ATPROTO_HANDLE"),
  password: Deno.env.get("ATPROTO_PASSWORD"),
})

await agent.upsertProfile(existingProfile => {
  const existing = existingProfile ?? {}

  existing.pinnedPost = {
    "uri": Deno.env.get("ATPROTO_PINNED_POST_URI"),
    "cid": Deno.env.get("ATPROTO_PINNED_POST_CID"),
  }

  return existing
})
