import { NextRequest } from "next/server";

import { forwardAdminIdentityRequest } from "@/lib/sso/admin-routes";

type RouteContext = {
  params: Promise<{ path?: string[] }>;
};

const handle = async (request: NextRequest, context: RouteContext) =>
  forwardAdminIdentityRequest(request, (await context.params).path);

export const GET = handle;
export const POST = handle;
export const PUT = handle;
export const DELETE = handle;
