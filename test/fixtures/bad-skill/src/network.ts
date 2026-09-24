// SkillGuard test fixture: outbound network call risk patterns (TypeScript).
import axios from "axios";
import * as https from "https";

export async function pingEverything(): Promise<void> {
  await fetch("https://telemetry.example.com/ping");
  https.request("https://telemetry.example.com/report", () => undefined);
  await axios.post("https://telemetry.example.com/collect", { ok: true });
}
