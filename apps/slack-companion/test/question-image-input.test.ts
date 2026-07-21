import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  planSlackQuestionImageInput,
  QuestionImageInputError,
  resolveQuestionImageInput,
} from "../src/question-work/image-input.js";

describe("Slack question image input", () => {
  it("plans captioned and image-only questions without persisting image bytes", () => {
    const captioned = planSlackQuestionImageInput({
      question: "  What is wrong in this screenshot? ",
      files: [{ file_ref: "slack-file://F1", mime_type: "image/png", name: "error.png", size_bytes: 1024 }],
    });
    assert.deepEqual(captioned, {
      manifest: {
        images: [{ declared_bytes: 1024, file_ref: "slack-file://F1", mime_type: "image/png", name: "error.png" }],
        schema_version: "question-image-input/v1",
        total_declared_bytes: 1024,
      },
      question: "What is wrong in this screenshot?",
      required_capability_refs: ["agent.input.image", "slack.files.read"],
      schema_version: "question-image-plan/v1",
    });
    assert.equal(JSON.stringify(captioned).includes("base64"), false);

    const imageOnly = planSlackQuestionImageInput({
      files: [{ file_ref: "slack-file://F2", mime_type: "image/jpeg" }],
    });
    assert.equal(imageOnly.question, "Inspect the attached image and explain what it shows.");
  });

  it("resolves authenticated host bytes into model-ready image content", async () => {
    const plan = planSlackQuestionImageInput({
      question: "Read this screenshot.",
      files: [{ file_ref: "slack-file://F1", mime_type: "image/png", size_bytes: 4 }],
    });
    const calls: unknown[][] = [];
    const readImage = async (...args: Parameters<import("../src/question-work/image-input.js").QuestionImageResolverPort["readImage"]>) => {
      calls.push(args);
      return {
      bytes: new Uint8Array([137, 80, 78, 71]),
      mime_type: "image/png",
      };
    };

    const images = await resolveQuestionImageInput(plan.manifest!, { readImage });

    assert.deepEqual(calls, [[plan.manifest!.images[0], 4 * 1024 * 1024]]);
    assert.deepEqual(images, [{ data: "iVBORw==", mimeType: "image/png", type: "image" }]);
  });

  it("rejects unsupported, oversized, mismatched, and empty host results", async () => {
    assert.throws(
      () => planSlackQuestionImageInput({
        question: "Inspect this.",
        files: [{ file_ref: "slack-file://F1", mime_type: "image/svg+xml", size_bytes: 100 }],
      }),
      new QuestionImageInputError("Cerebro can inspect PNG, JPEG, WebP, and GIF images in Slack."),
    );

    assert.throws(
      () => planSlackQuestionImageInput({
        question: "Inspect this.",
        files: [{ file_ref: "slack-file://F1", mime_type: "image/png", size_bytes: 4 * 1024 * 1024 + 1 }],
      }),
      new QuestionImageInputError("Each Slack image must be 4 MB or smaller."),
    );

    const plan = planSlackQuestionImageInput({
      question: "Inspect this.",
      files: [{ file_ref: "slack-file://F1", mime_type: "image/png" }],
    });
    await assert.rejects(resolveQuestionImageInput(plan.manifest!, {
      readImage: async () => ({ bytes: new Uint8Array([1]), mime_type: "image/jpeg" }),
    }), /does not match its file metadata/);
    await assert.rejects(resolveQuestionImageInput(plan.manifest!, {
      readImage: async () => ({ bytes: new Uint8Array(), mime_type: "image/png" }),
    }), /empty or unavailable/);
  });
});
