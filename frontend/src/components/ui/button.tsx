import React from "react";
import { cn } from "../../lib/utils";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "default" | "destructive" | "outline" | "secondary" | "ghost" | "link";
  size?: "default" | "sm" | "lg" | "icon";
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", size = "default", ...props }, ref) => {
    const variants = {
      default: "bg-blue-600 text-white hover:bg-blue-500 shadow-md shadow-blue-900/20 active:scale-[0.98]",
      destructive: "bg-red-600 text-white hover:bg-red-500 shadow-md shadow-red-900/20 active:scale-[0.98]",
      outline: "border border-slate-700 bg-slate-900/50 hover:bg-slate-800 text-slate-200 active:scale-[0.98]",
      secondary: "bg-slate-800 text-slate-100 hover:bg-slate-700 active:scale-[0.98]",
      ghost: "hover:bg-slate-800/80 text-slate-300 hover:text-white",
      link: "text-blue-400 underline-offset-4 hover:underline",
    };

    const sizes = {
      default: "h-9 px-4 py-2 text-sm",
      sm: "h-8 rounded-md px-3 text-xs",
      lg: "h-11 rounded-md px-8 text-base",
      icon: "h-9 w-9 p-0",
    };

    return (
      <button
        ref={ref}
        className={cn(
          "inline-flex items-center justify-center whitespace-nowrap rounded-lg font-medium transition-all focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-blue-500 disabled:pointer-events-none disabled:opacity-50 gap-2 cursor-pointer",
          variants[variant],
          sizes[size],
          className
        )}
        {...props}
      />
    );
  }
);

Button.displayName = "Button";
