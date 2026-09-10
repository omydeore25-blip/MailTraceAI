import React from "react";
import { cn } from "../../lib/utils";

interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  value?: number;
  max?: number;
  indicatorClassName?: string;
}

export const Progress: React.FC<ProgressProps> = ({
  className,
  value = 0,
  max = 100,
  indicatorClassName,
  ...props
}) => {
  const percentage = Math.min(100, Math.max(0, (value / max) * 100));

  return (
    <div
      className={cn("relative h-2 w-full overflow-hidden rounded-full bg-slate-800", className)}
      {...props}
    >
      <div
        className={cn("h-full bg-blue-600 transition-all duration-500 ease-out", indicatorClassName)}
        style={{ width: `${percentage}%` }}
      />
    </div>
  );
};
