import { describe, expect, it, vi } from "vitest";

import { downloadMarkdown } from "@/lib/api";

describe("Markdown report downloads", () => {
  it("uses the authenticated response filename and triggers a browser download", async () => {
    const click = vi.fn();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("# Report", {
      status: 200,
      headers: { "content-disposition": "attachment; filename*=UTF-8''sentivra-report-test.md", "content-type": "text/markdown" },
    })));
    vi.spyOn(document, "createElement").mockReturnValue({
      href: "", download: "", click, remove: vi.fn(),
    } as unknown as HTMLElement);
    vi.spyOn(document.body, "appendChild").mockImplementation((node) => node);
    vi.stubGlobal("URL", { createObjectURL: vi.fn().mockReturnValue("blob:test"), revokeObjectURL: vi.fn() });

    await expect(downloadMarkdown("/report.md", "fallback.md")).resolves.toBe("sentivra-report-test.md");
    expect(click).toHaveBeenCalledOnce();
  });
});
