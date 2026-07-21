"use client";

import Image from "next/image";
import { ImagePlus, X } from "lucide-react";
import { useRef, useState } from "react";

import { addAskImageFiles, type AskImageAttachment } from "@/lib/ask-images";

export default function ImageAttachments({
  disabled = false,
  images,
  onChange,
}: {
  disabled?: boolean;
  images: AskImageAttachment[];
  onChange: (images: AskImageAttachment[]) => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);

  const addFiles = async (files: File[]) => {
    const result = await addAskImageFiles(images, files);
    onChange(result.images);
    setError(result.error);
  };

  return (
    <div className="space-y-2">
      {images.length > 0 && (
        <div className="flex flex-wrap gap-2 px-3 pt-2">
          {images.map((image) => (
            <div key={image.id} className="group relative h-16 w-16 overflow-hidden rounded-md border border-slate-200 bg-slate-50">
              <Image src={image.data_url} alt={image.name} fill unoptimized className="object-cover" />
              <button
                type="button"
                onClick={() => onChange(images.filter((candidate) => candidate.id !== image.id))}
                disabled={disabled}
                aria-label={`Remove ${image.name}`}
                className="absolute right-1 top-1 grid h-5 w-5 place-items-center rounded-full bg-slate-950/80 text-white opacity-0 transition group-hover:opacity-100 focus:opacity-100 disabled:hidden"
              >
                <X className="h-3 w-3" />
              </button>
            </div>
          ))}
        </div>
      )}
      <div className="flex items-center gap-2 px-3 pb-1">
        <input
          ref={inputRef}
          type="file"
          accept="image/png,image/jpeg,image/webp,image/gif"
          multiple
          className="sr-only"
          disabled={disabled}
          onChange={(event) => {
            void addFiles(Array.from(event.target.files ?? []));
            event.target.value = "";
          }}
        />
        <button
          type="button"
          onClick={() => inputRef.current?.click()}
          disabled={disabled}
          className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-[12px] font-medium text-slate-500 transition hover:bg-slate-50 hover:text-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
        >
          <ImagePlus className="h-4 w-4" />
          Add images
        </button>
        <span className="text-[11px] text-slate-400">PNG, JPEG, WebP, or GIF. 4 MB each.</span>
      </div>
      {error && <p role="alert" className="px-3 pb-1 text-[12px] text-rose-700">{error}</p>}
    </div>
  );
}
