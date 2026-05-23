import { redirect } from "next/navigation";
import { getCurrentUser } from "@/lib/server/auth/session";
import SettingsForm from "./SettingsForm";

export const dynamic = "force-dynamic";

export default async function SettingsPage() {
  const { user } = await getCurrentUser();
  if (!user) redirect("/login");
  return <SettingsForm user={user} />;
}
