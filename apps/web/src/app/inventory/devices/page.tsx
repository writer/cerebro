import { redirect } from "next/navigation";

type InventoryDevicesRedirectPageProps = {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
};

// Devices are a Group filter on the main inventory search, so the old preset
// route forwards there and keeps any search the link carried.
export default async function InventoryDevicesRedirectPage({ searchParams }: InventoryDevicesRedirectPageProps) {
  const params = await searchParams;
  const query = new URLSearchParams();

  Object.entries(params ?? {}).forEach(([key, value]) => {
    if (key === "group") return;
    if (Array.isArray(value)) {
      value.forEach((entry) => query.append(key, entry));
      return;
    }
    if (value !== undefined) query.set(key, value);
  });
  query.set("group", "devices");

  redirect(`/inventory?${query.toString()}`);
}
