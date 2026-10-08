import { redirect } from "next/navigation";

type LegacySourceActivationRedirectPageProps = {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
};

export default async function LegacySourceActivationRedirectPage({ searchParams }: LegacySourceActivationRedirectPageProps) {
  const params = await searchParams;
  const query = new URLSearchParams();

  Object.entries(params ?? {}).forEach(([key, value]) => {
    if (Array.isArray(value)) {
      value.forEach((entry) => query.append(key, entry));
      return;
    }
    if (value !== undefined) query.set(key, value);
  });

  const queryString = query.toString();
  redirect(`/connectors/activation${queryString ? `?${queryString}` : ""}`);
}
