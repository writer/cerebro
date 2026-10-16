import { useId } from "react";

// Mirrors src/app/icon.svg so the favicon and the in-app mark stay identical.
export default function CerebroMark({ className, title }: { className?: string; title?: string }) {
  // Gradient ids are document-global; a per-instance id keeps two marks on one
  // page from resolving each other's gradients.
  const id = useId().replace(/:/g, "");
  return (
    <svg
      viewBox="0 0 64 64"
      fill="none"
      className={className}
      role={title ? "img" : undefined}
      aria-hidden={title ? undefined : true}
      aria-label={title}
    >
      <defs>
        <linearGradient id={`${id}-bg`} x1="6" y1="4" x2="58" y2="62" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#6D5BFF" />
          <stop offset="0.55" stopColor="#5B3FF0" />
          <stop offset="1" stopColor="#3B1FB8" />
        </linearGradient>
        <radialGradient id={`${id}-hi`} cx="20" cy="10" r="44" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#FFFFFF" stopOpacity="0.32" />
          <stop offset="1" stopColor="#FFFFFF" stopOpacity="0" />
        </radialGradient>
        <radialGradient id={`${id}-core`} cx="32" cy="32" r="5.2" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#B8FFF1" />
          <stop offset="1" stopColor="#2EE6C5" />
        </radialGradient>
      </defs>
      <rect width="64" height="64" rx="15" fill={`url(#${id}-bg)`} />
      <rect width="64" height="64" rx="15" fill={`url(#${id}-hi)`} />
      <rect x="0.75" y="0.75" width="62.5" height="62.5" rx="14.25" stroke="#FFFFFF" strokeOpacity="0.18" strokeWidth="1.5" />
      <path d="M43.3 20.7A16 16 0 1 0 43.3 43.3" stroke="#FFFFFF" strokeWidth="5" strokeLinecap="round" />
      <path d="M43.3 20.7L32 32" stroke="#FFFFFF" strokeOpacity="0.85" strokeWidth="3" strokeLinecap="round" />
      <circle cx="43.3" cy="20.7" r="4.2" fill="#FFFFFF" />
      <circle cx="43.3" cy="43.3" r="4.2" fill="#FFFFFF" />
      <circle cx="32" cy="32" r="5.2" fill={`url(#${id}-core)`} />
    </svg>
  );
}
