declare module "*.png";
declare module "*/leekr-font.svg" {
    import * as React from "react";
    const LeekrFont: React.FunctionComponent<React.SVGProps<SVGSVGElement> & { title?: string }>;
    export default LeekrFont;
}
declare module "*/settings-font.svg" {
    import * as React from "react";
    const SettingsFont: React.FunctionComponent<React.SVGProps<SVGSVGElement> & { title?: string }>;
    export default SettingsFont;
}
