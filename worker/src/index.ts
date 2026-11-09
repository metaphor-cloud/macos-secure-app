import { gate, notFound } from "./gate";
import { route } from "./routes";
import type { Bindings } from "./types";

export { LiveHub } from "./lib/hub";

export default {
  async fetch(request: Request, env: Bindings, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const result = await gate(request, url, env);
    if (result.kind === "response") return result.response;
    // Only /api exists. The app's page is bundled inside the Mac app, not served from here.
    if (result.kind === "outside") return notFound();
    return route({ request, url, env, ctx, identity: result.identity });
  },
} satisfies ExportedHandler<Bindings>;
